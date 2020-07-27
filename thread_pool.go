package common

import (
	"context"
	"log"
)

type ThreadPool struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dispatcher *Dispatcher
}

func NewThreadPool(maxWorkers, maxQueue int) *ThreadPool {
	ctx, cancel := context.WithCancel(context.Background())

	threadPool := &ThreadPool{
		ctx:        ctx,
		cancel:     cancel,
		dispatcher: newDispatcher(maxWorkers, maxQueue),
	}
	go threadPool.dispatcher.run(ctx)
	return threadPool
}

func (threadPool *ThreadPool) Queue(f func() error) {
	select {
	case threadPool.dispatcher.jobQueue <- f:
	default:
	}
}

func (threadPool *ThreadPool) Stop() {
	go func() {
		threadPool.cancel()
	}()
}

type Worker struct {
	workerPool  chan chan func() error // nguoi giao viec
	joinChannel chan func() error      // cong viec
}

type Dispatcher struct {
	maxWorkers int
	workerPool chan chan func() error
	jobQueue   chan func() error
}

func newWorker(workerPool chan chan func() error) Worker {
	return Worker{
		workerPool:  workerPool,
		joinChannel: make(chan func() error),
	}
}

func newDispatcher(maxWorkers, maxQueue int) *Dispatcher {
	return &Dispatcher{
		maxWorkers: maxWorkers,
		workerPool: make(chan chan func() error, maxWorkers),
		jobQueue:   make(chan func() error, maxQueue),
	}
}

func (w Worker) start(ctx context.Context) {
	go func() {
		for {
			// thông báo cho ng giao việc là mình sẵn sàng nhận việc
			w.workerPool <- w.joinChannel
			select {
			// đợi đến lúc giao việc rồi làm
			case job := <-w.joinChannel:
				if err := job(); err != nil {
					log.Println(err)
				}
			case <-ctx.Done():
				close(w.joinChannel)
				return
			}
		}
	}()
}

func (d *Dispatcher) dispatch(ctx context.Context) {
	for {
		select {
		// nhận dự án, công việc về cty
		case job := <-d.jobQueue:
			go func(job func() error) {
				//lấy thằng nhân viên đang rảnh rỗi ra ngoài
				jobChannel := <-d.workerPool
				// giao việc cho nó
				jobChannel <- job
			}(job)
		case <-ctx.Done():
			close(d.jobQueue)
			close(d.workerPool)
			return
		}
	}
}

func (d *Dispatcher) run(ctx context.Context) {
	for i := 0; i < d.maxWorkers; i++ {
		worker := newWorker(d.workerPool)
		worker.start(ctx)
	}

	d.dispatch(ctx)
}