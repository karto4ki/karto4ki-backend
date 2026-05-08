package services

import (
	"sync"
)

// counterMu - счётчик блокировок для ключа
type counterMu struct {
	mu     sync.Mutex
	locked int
}

// Locker - блокировка в памяти (как в chakchat)
type Locker struct {
	keyMu map[string]*counterMu
	mu    sync.Mutex
}

// NewLocker создаёт новую блокировку
func NewLocker() *Locker {
	return &Locker{
		keyMu: make(map[string]*counterMu),
	}
}

// Lock блокирует ключ
func (l *Locker) Lock(key string) {
	l.mu.Lock()
	keyed, ok := l.keyMu[key]
	if !ok {
		keyed = new(counterMu)
		l.keyMu[key] = keyed
	}
	keyed.locked++
	l.mu.Unlock()

	keyed.mu.Lock()
}

// Unlock разблокирует ключ
func (l *Locker) Unlock(key string) {
	l.mu.Lock()
	keyed, ok := l.keyMu[key]
	if !ok {
		// Неизвестный ключ
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	keyed.mu.Unlock()

	l.mu.Lock()
	keyed.locked--
	if keyed.locked <= 0 {
		delete(l.keyMu, key)
	}
	l.mu.Unlock()
}
