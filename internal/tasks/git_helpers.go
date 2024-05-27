package tasks

import (
	"github.com/flightctl/flightctl/internal/store/model"
	"github.com/flightctl/flightctl/internal/tasks/repotester"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	gitplumbing "github.com/go-git/go-git/v5/plumbing"
	gitmemory "github.com/go-git/go-git/v5/storage/memory"
)

// a function to clone a git repo, for mockable unit testing
type cloneGitRepoFunc func(repo *model.Repository, revision *string, depth *int) (billy.Filesystem, string, error)

func CloneGitRepo(repo *model.Repository, revision *string, depth *int) (billy.Filesystem, string, error) {
	storage := gitmemory.NewStorage()
	mfs := memfs.New()
	opts := &git.CloneOptions{
		URL: *repo.Spec.Data.Repo,
	}
	if depth != nil {
		opts.Depth = *depth
	}
	auth, err := repotester.GetAuth(repo)
	if err != nil {
		return nil, "", err
	}
	opts.Auth = auth
	if revision != nil {
		opts.ReferenceName = gitplumbing.ReferenceName(*revision)
	}
	gitRepo, err := git.Clone(storage, mfs, opts)
	if err != nil {
		return nil, "", err
	}
	head, err := gitRepo.Head()
	if err != nil {
		return nil, "", err
	}
	hash := head.Hash().String()
	return mfs, hash, nil
}
