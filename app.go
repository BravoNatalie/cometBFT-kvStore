package main

import (
	"bytes"
	"context"
	"errors"
	"log"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/dgraph-io/badger"
)

type KVStoreApplication struct {
    db           *badger.DB
    onGoingBlock *badger.Txn
}

var _ abcitypes.Application = (*KVStoreApplication)(nil)

func NewKVStoreApplication(db *badger.DB) *KVStoreApplication {
    return &KVStoreApplication{db: db}
}

func (app *KVStoreApplication) Info(_ context.Context, info *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
    return &abcitypes.ResponseInfo{}, nil
}

func (app *KVStoreApplication) Query(_ context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
    resp := abcitypes.ResponseQuery{Key: req.Data}

    dbErr := app.db.View(func(txn *badger.Txn) error {
        item, err := txn.Get(req.Data)
        if err != nil {
            if !errors.Is(err, badger.ErrKeyNotFound) {
                return err
            }
            resp.Log = "key does not exist"
            return nil
        }

        return item.Value(func(val []byte) error {
            resp.Log = "exists"
            resp.Value = val
            return nil
        })
    })
    if dbErr != nil {
        log.Panicf("Error reading database, unable to execute query: %v", dbErr)
    }
    return &resp, nil
}

// verifies if the transaction can be executed
func (app *KVStoreApplication) CheckTx(_ context.Context, check *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
    code := app.isValid(check.Tx)
    return &abcitypes.ResponseCheckTx{Code: code}, nil
}

func (app *KVStoreApplication) InitChain(_ context.Context, chain *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
    return &abcitypes.ResponseInitChain{}, nil
}


// PrepareProposal is called when validated transactions, passed through CheckTx, are ready to be included in blocks. 
// It allows the application to modify the group of transactions before they are proposed.
func (app *KVStoreApplication) PrepareProposal(_ context.Context, proposal *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
    // Returns the group of transactions unmodified.
    return &abcitypes.ResponsePrepareProposal{Txs: proposal.Txs}, nil
}


// ProcessProposal is called when a proposed block is received by a node. 
// The proposal is passed to the application for validation before voting on whether to accept it. 
// This step helps in identifying and dealing with blocks that may have been manipulated by malicious nodes.
func (app *KVStoreApplication) ProcessProposal(_ context.Context, proposal *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
    // Automatically accepts all proposals without modification.
    return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}


// responsible for executing the block and returning a response to the consensus engine.
func (app *KVStoreApplication) FinalizeBlock(_ context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
    var txs = make([]*abcitypes.ExecTxResult, len(req.Txs))

    app.onGoingBlock = app.db.NewTransaction(true)
    for i, tx := range req.Txs {
        // Transactions are not guaranteed to be valid when they are delivered to an application, even if they were valid when they were proposed.
        if code := app.isValid(tx); code != 0 {
            log.Printf("Error: invalid transaction index %v", i)
            txs[i] = &abcitypes.ExecTxResult{Code: code}
        } else {
            parts := bytes.SplitN(tx, []byte("="), 2)
            key, value := parts[0], parts[1]
            log.Printf("Adding key %s with value %s", key, value)

            if err := app.onGoingBlock.Set(key, value); err != nil {
                log.Panicf("Error writing to database, unable to execute tx: %v", err)
            }

            log.Printf("Successfully added key %s with value %s", key, value)

            // Add an event for the transaction execution.
            // Multiple events can be emitted for a transaction, but we are adding only one event
            txs[i] = &abcitypes.ExecTxResult{
                Code: 0,
                Events: []abcitypes.Event{
                    {
                        Type: "app",
                        Attributes: []abcitypes.EventAttribute{
                            {Key: "key", Value: string(key), Index: true},
                            {Key: "value", Value: string(value), Index: true},
                        },
					},
				},
			}
        }
    }

    return &abcitypes.ResponseFinalizeBlock{
      TxResults:        txs,
    }, nil
}

// The Commit method tells the application to make permanent the effects of the application transactions. The state is finally updated.
func (app KVStoreApplication) Commit(_ context.Context, commit *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
    return &abcitypes.ResponseCommit{}, app.onGoingBlock.Commit()
}

func (app *KVStoreApplication) ListSnapshots(_ context.Context, snapshots *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
    return &abcitypes.ResponseListSnapshots{}, nil
}

func (app *KVStoreApplication) OfferSnapshot(_ context.Context, snapshot *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
    return &abcitypes.ResponseOfferSnapshot{}, nil
}

func (app *KVStoreApplication) LoadSnapshotChunk(_ context.Context, chunk *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
    return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

func (app *KVStoreApplication) ApplySnapshotChunk(_ context.Context, chunk *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
    return &abcitypes.ResponseApplySnapshotChunk{Result: abcitypes.ResponseApplySnapshotChunk_ACCEPT}, nil
}

func (app KVStoreApplication) ExtendVote(_ context.Context, extend *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
    return &abcitypes.ResponseExtendVote{}, nil
}

func (app *KVStoreApplication) VerifyVoteExtension(_ context.Context, verify *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
    return &abcitypes.ResponseVerifyVoteExtension{}, nil
}

func (app *KVStoreApplication) isValid(tx []byte) uint32 {
    // check format
    parts := bytes.Split(tx, []byte("="))
    if len(parts) != 2 {
        return 1
    }

    return 0
}