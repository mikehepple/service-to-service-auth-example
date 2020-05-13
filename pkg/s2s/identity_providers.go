package s2s

type IdentityProvider interface {
	Find(name string) (ServiceIdentity, bool)
}

type ServiceIdentities []ServiceIdentity

func (s ServiceIdentities) Find(name string) (ServiceIdentity, bool) {
	for _, identity := range s {
		if identity.name == name {
			return identity, true
		}
	}
	return ServiceIdentity{}, false
}
