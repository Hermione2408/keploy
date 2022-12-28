package mock

import (
	"context"

	proto "go.keploy.io/server/grpc/regression"

	"go.keploy.io/server/pkg/models"
)

const (
	ERR_DEP_REQ_UNEQUAL_INSERT string = "the stored external dependency output is not for the current dependency request call. Insert the new mock"
	ERR_DEP_REQ_UNEQUAL_REMOVE string = "a set of dependency calls are removed. Remove the adjacent set of mocks from the mock file"
)

type Service interface {
	Put(ctx context.Context, path string, doc models.Mock, meta interface{}) error
	GetAll(ctx context.Context, path string, name string) ([]models.Mock, error)
	FileExists(ctx context.Context, path string) bool
	IsEqual(ctx context.Context, old, new *proto.Mock, path, name string, updateCount int) error
	CompareMockResponses(old, new *proto.Mock) bool
}
