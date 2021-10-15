package main

type Data struct {
	meta  *Metadata
	value map[string]interface{} // string is the key for the prefix or range or ip address
}

func (d *Data) GetMeta() *Metadata {
	return d.meta
}

func (d *Data) GetValue() map[string]interface{} {
	return d.value
}

func (d *Data) AddValue(p string, v interface{}) {
	d.value[p] = v
}

func (d *Data) DeleteValue(p string) {
	delete(d.value, p)
}

type Metadata struct {
	ipPrefix  bool
	ipRange   bool
	ipAddress bool
}

func (m *Metadata) HasIpPrefix() bool {
	return m.ipPrefix
}

func (m *Metadata) HasIpRange() bool {
	return m.ipRange
}

func (m *Metadata) HasIpAddress() bool {
	return m.ipAddress
}

func (m *Metadata) SetIpPrefix() {
	m.ipPrefix = true
}

func (m *Metadata) SetIpRange() {
	m.ipRange = true
}

func (m *Metadata) SetIpAddress() {
	m.ipAddress = true
}

func (m *Metadata) ResetIpPrefix() {
	m.ipPrefix = false
}

func (m *Metadata) ResetIpRange() {
	m.ipRange = false
}

func (m *Metadata) ResetIpAddress() {
	m.ipAddress = false
}