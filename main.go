package main

import (
	"fmt"
	"gTLSInfo/common"
	"gTLSInfo/pipeline"
	"runtime"
)

func main() {
	r, err := pipeline.NewPipeline(&common.TaskOptions{
		Concurrency: runtime.NumCPU() * 2,
	})
	if err != nil {
		panic(err)
	}

	go func() {
		for result := range r.Results() {
			fmt.Println(result)
		}
	}()

	if err := r.ExecutePipeline(); err != nil {
		panic(err)
	}
}
