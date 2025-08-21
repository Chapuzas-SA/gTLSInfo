package pipeline

import (
	"bufio"
	"encoding/json"
	"gTLSInfo/common"
	"gTLSInfo/normalize"
	"gTLSInfo/tlsclient"
	"os"
	"sync"
)

type PipelineOptions struct {
	Options     *common.TaskOptions
	ResultsChan chan string
}

func NewPipeline(options *common.TaskOptions) (*PipelineOptions, error) {
	return &PipelineOptions{
		Options:     options,
		ResultsChan: make(chan string, options.Concurrency),
	}, nil
}

func (r *PipelineOptions) ExecutePipeline() error {
	inputChan := make(chan common.Normalized, r.Options.Concurrency)
	wg := &sync.WaitGroup{}

	go func() {
		wg.Wait()
		close(r.ResultsChan)
	}()

	for i := 0; i < r.Options.Concurrency; i++ {
		wg.Add(1)
		go r.processInputElement(inputChan, wg)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			if targets, err := normalize.NormalizeLine(line); err == nil {
				for _, target := range targets {
					inputChan <- target
				}
			}
		}
	}
	close(inputChan)

	wg.Wait()
	return scanner.Err()
}

func (r *PipelineOptions) processInputElement(inputs chan common.Normalized, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range inputs {
		res := tlsclient.ProcessTLSInfo(task.Host, task.Port)
		if len(res.Versions) > 0 {
			jsonBytes, err := json.Marshal(res)
			if err == nil {
				r.ResultsChan <- string(jsonBytes)
			}
		}
	}
}

func (r *PipelineOptions) Results() <-chan string {
	return r.ResultsChan
}

func (r *PipelineOptions) ClosePipeline() error {
	return nil
}
