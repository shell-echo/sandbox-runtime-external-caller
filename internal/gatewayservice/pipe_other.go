//go:build !darwin && !linux

package gatewayservice

import "os"

func OpenCommandPipe(int) (*os.File, error)          { return nil, ErrControl }
func OpenBackendPipe(int) (*os.File, error)          { return nil, ErrControl }
func DuplicateOutputPipe(*os.File) (*os.File, error) { return nil, ErrControl }
