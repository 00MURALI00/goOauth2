package store

import (
	"github.com/00MURALI00/goOauth2/models"
)

type MemoryStore struct {
	Users   map[string]models.User
	Clients map[string]models.Client
	Codes   map[string]models.AuthorizationCode
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Users:   make(map[string]models.User),
		Clients: make(map[string]models.Client),
		Codes:   make(map[string]models.AuthorizationCode),
	}
}

// Users methods

func (ms *MemoryStore) GetUser(username string) (models.User, bool) {
	user, ok := ms.Users[username]
	return user, ok
}

func (ms *MemoryStore) GetUserByUsername(username string) (models.User, bool) {
	for _, user := range ms.Users {
		if user.Username == username {
			return user, true
		}
	}
	return models.User{}, false
}

func (ms *MemoryStore) SaveUserById(user models.User) {
	if user.UserId != "" {
		ms.Users[user.UserId] = user
	}
}

func (ms *MemoryStore) DeleteUserWithUserId(userId string) {
	delete(ms.Users, userId)
}

// Clients methods

func (ms *MemoryStore) GetClient(clientId string) (models.Client, bool) {
	client, ok := ms.Clients[clientId]
	return client, ok
}

func (ms *MemoryStore) SaveClient(client models.Client) {
	if client.ClientId != "" {
		ms.Clients[client.ClientId] = client
	}
}

func (ms *MemoryStore) DeleteClient(clientId string) {
	delete(ms.Clients, clientId)
}

// Codes methods

func (ms *MemoryStore) GetCode(code string) (models.AuthorizationCode, bool) {
	ac, ok := ms.Codes[code]
	return ac, ok
}

func (ms *MemoryStore) SaveCode(ac models.AuthorizationCode) {
	if ac.Code != "" {
		ms.Codes[ac.Code] = ac
	}
}

func (ms *MemoryStore) DeleteCode(code string) {
	delete(ms.Codes, code)
}
