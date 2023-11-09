// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package fhevm

/*
#cgo linux CFLAGS: -O3 -I../tfhe-rs/target/release
#cgo linux LDFLAGS: -L../tfhe-rs/target/release -l:libtfhe.a -lm
#cgo darwin CFLAGS: -O3 -I../tfhe-rs/target/release
#cgo darwin LDFLAGS: -framework Security -L../tfhe-rs/target/release -ltfhe -lm

#include <tfhe.h>

#undef NDEBUG
#include <assert.h>

typedef struct FhevmKeys{
	void *sks, *cks, *pks;
} FhevmKeys;

FhevmKeys generate_fhevm_keys(){
	ConfigBuilder* builder;
	Config *config;
	ClientKey *cks;
	ServerKey *sks;
	CompactPublicKey *pks;

	int r;
	r = config_builder_all_disabled(&builder);
	assert(r == 0);
	r = config_builder_enable_custom_integers(&builder, SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
	assert(r == 0);
	r = config_builder_build(builder, &config);
	assert(r == 0);
	r = generate_keys(config, &cks, &sks);
	assert(r == 0);
	r = compact_public_key_new(cks, &pks);
	assert(r == 0);

	FhevmKeys keys = {sks, cks, pks};
	return keys;
}

int serialize_compact_public_key(void *pks, Buffer* out) {
	return compact_public_key_serialize(pks, out);
}

void* deserialize_server_key(BufferView in) {
	ServerKey* sks = NULL;
	const int r = server_key_deserialize(in, &sks);
	assert(r == 0);
	return sks;
}

void* deserialize_client_key(BufferView in) {
	ClientKey* cks = NULL;
	const int r = client_key_deserialize(in, &cks);
	assert(r == 0);
	return cks;
}

void* deserialize_compact_public_key(BufferView in) {
	CompactPublicKey* pks = NULL;
	const int r = compact_public_key_deserialize(in, &pks);
	assert(r == 0);
	return pks;
}

void checked_set_server_key(void *sks) {
	const int r = set_server_key(sks);
	assert(r == 0);
}

int serialize_fhe_uint8(void *ct, Buffer* out) {
	return fhe_uint8_serialize(ct, out);
}

void* deserialize_fhe_uint8(BufferView in) {
	FheUint8* ct = NULL;
	const int r = fhe_uint8_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint8(BufferView in) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint8_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint8_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint16(void *ct, Buffer* out) {
	return fhe_uint16_serialize(ct, out);
}

void* deserialize_fhe_uint16(BufferView in) {
	FheUint16* ct = NULL;
	const int r = fhe_uint16_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint16(BufferView in) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint16_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint16_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint32(void *ct, Buffer* out) {
	return fhe_uint32_serialize(ct, out);
}

void* deserialize_fhe_uint32(BufferView in) {
	FheUint32* ct = NULL;
	const int r = fhe_uint32_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint32(BufferView in) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint32_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint32_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
	return ct;
}

void destroy_fhe_uint8(void* ct) {
	const int r = fhe_uint8_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint16(void* ct) {
	const int r = fhe_uint16_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint32(void* ct) {
	const int r = fhe_uint32_destroy(ct);
	assert(r == 0);
}

void* add_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

int decrypt_fhe_uint8(void* cks, void* ct, uint8_t* res)
{
	*res = 0;
	return fhe_uint8_decrypt(ct, cks, res);
}

int decrypt_fhe_uint16(void* cks, void* ct, uint16_t* res)
{
	*res = 0;
	return fhe_uint16_decrypt(ct, cks, res);
}

int decrypt_fhe_uint32(void* cks, void* ct, uint32_t* res)
{
	*res = 0;
	return fhe_uint32_decrypt(ct, cks, res);
}

void* public_key_encrypt_fhe_uint8(void* pks, uint8_t value) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint16(void* pks, uint16_t value) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint32(void* pks, uint32_t value) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint8(void* sks, uint8_t value) {
	FheUint8* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint8_try_encrypt_trivial_u8(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint16(void* sks, uint16_t value) {
	FheUint16* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint16_try_encrypt_trivial_u16(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint32(void* sks, uint32_t value) {
	FheUint32* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint32_try_encrypt_trivial_u32(value, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt_and_serialize_fhe_uint8_list(void* pks, uint8_t value, Buffer* out) {
	CompactFheUint8List* list = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint16_list(void* pks, uint16_t value, Buffer* out) {
	CompactFheUint16List* list = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint32_list(void* pks, uint32_t value, Buffer* out) {
	CompactFheUint32List* list = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
}

void* cast_8_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

*/
import "C"

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"unsafe"
)

func toBufferView(in []byte) C.BufferView {
	return C.BufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

// Expanded TFHE ciphertext sizes by type, in bytes.
var expandedFheCiphertextSize map[FheUintType]uint

// Compact TFHE ciphertext sizes by type, in bytes.
var compactFheCiphertextSize map[FheUintType]uint

// server key: evaluation key
var sks unsafe.Pointer

// client key: secret key
var cks unsafe.Pointer

// public key
var pks unsafe.Pointer
var pksHash Hash

// Generate keys for the fhevm (sks, cks, psk)
func generateFhevmKeys() (unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) {
	var keys = C.generate_fhevm_keys()
	return keys.sks, keys.cks, keys.pks
}

func globalKeysPresent() bool {
	return sks != nil && cks != nil && pks != nil
}

func initGlobalKeysWithNewKeys() {
	sks, cks, pks = generateFhevmKeys()
	initCiphertextSizes()
}

func initCiphertextSizes() {
	expandedFheCiphertextSize = make(map[FheUintType]uint)
	compactFheCiphertextSize = make(map[FheUintType]uint)

	expandedFheCiphertextSize[FheUint8] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint8).serialize()))
	expandedFheCiphertextSize[FheUint16] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint16).serialize()))
	expandedFheCiphertextSize[FheUint32] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint32).serialize()))

	compactFheCiphertextSize[FheUint8] = uint(len(encryptAndSerializeCompact(0, FheUint8)))
	compactFheCiphertextSize[FheUint16] = uint(len(encryptAndSerializeCompact(0, FheUint16)))
	compactFheCiphertextSize[FheUint32] = uint(len(encryptAndSerializeCompact(0, FheUint32)))
}

func InitGlobalKeysFromFiles(keysDir string) error {
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		return errors.New("init_keys: global keys directory doesn't exist (FHEVM_GO_KEYS_DIR)")
	}
	// read keys from files
	var sksPath = path.Join(keysDir, "sks")
	sksBytes, err := os.ReadFile(sksPath)
	if err != nil {
		return err
	}
	var cksPath = path.Join(keysDir, "cks")
	cksBytes, err := os.ReadFile(cksPath)
	if err != nil {
		return err
	}
	var pksPath = path.Join(keysDir, "pks")
	pksBytes, err := os.ReadFile(pksPath)
	if err != nil {
		return err
	}

	sks = C.deserialize_server_key(toBufferView(sksBytes))

	pksHash = Keccak256Hash(pksBytes)
	pks = C.deserialize_compact_public_key(toBufferView(pksBytes))

	cks = C.deserialize_client_key(toBufferView(cksBytes))

	initCiphertextSizes()

	fmt.Println("INFO: global keys loaded from: " + keysDir)

	return nil
}

// initialize keys automatically only if FHEVM_GO_KEYS_DIR is set
func init() {
	var keysDirPath, present = os.LookupEnv("FHEVM_GO_KEYS_DIR")
	if present {
		err := InitGlobalKeysFromFiles(keysDirPath)
		if err != nil {
			panic(err)
		}
		fmt.Println("INFO: global keys are initialized automatically using FHEVM_GO_KEYS_DIR env variable")
	} else {
		fmt.Println("INFO: global keys aren't initialized automatically (FHEVM_GO_KEYS_DIR env variable not set)")
	}
}

func serialize(ptr unsafe.Pointer, t FheUintType) ([]byte, error) {
	out := &C.Buffer{}
	var ret C.int
	switch t {
	case FheUint8:
		ret = C.serialize_fhe_uint8(ptr, out)
	case FheUint16:
		ret = C.serialize_fhe_uint16(ptr, out)
	case FheUint32:
		ret = C.serialize_fhe_uint32(ptr, out)
	default:
		panic("serialize: unexpected ciphertext type")
	}
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize a ciphertext")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ser, nil
}

func serializePublicKey(pks unsafe.Pointer) ([]byte, error) {
	out := &C.Buffer{}
	var ret C.int
	ret = C.serialize_compact_public_key(pks, out)
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize public key")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ser, nil
}

// Represents a TFHE ciphertext type, i.e. its bit capacity.
type FheUintType uint8

const (
	FheUint8  FheUintType = 0
	FheUint16 FheUintType = 1
	FheUint32 FheUintType = 2
)

// Represents an expanded TFHE ciphertext.
type tfheCiphertext struct {
	serialization []byte
	hash          *Hash
	fheUintType   FheUintType
}

// Deserializes a TFHE ciphertext.
func (ct *tfheCiphertext) deserialize(in []byte, t FheUintType) error {
	switch t {
	case FheUint8:
		ptr := C.deserialize_fhe_uint8(toBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint8 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint8(ptr)
	case FheUint16:
		ptr := C.deserialize_fhe_uint16(toBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint16 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint16(ptr)
	case FheUint32:
		ptr := C.deserialize_fhe_uint32(toBufferView((in)))
		if ptr == nil {
			return errors.New("FheUint32 ciphertext deserialization failed")
		}
		C.destroy_fhe_uint32(ptr)
	default:
		panic("deserialize: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.serialization = in
	ct.computeHash()
	return nil
}

// Deserializes a compact TFHE ciphetext.
// Note: After the compact TFHE ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *tfheCiphertext) deserializeCompact(in []byte, t FheUintType) error {
	switch t {
	case FheUint8:
		ptr := C.deserialize_compact_fhe_uint8(toBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint8 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			return err
		}
	case FheUint16:
		ptr := C.deserialize_compact_fhe_uint16(toBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint16 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			return err
		}
	case FheUint32:
		ptr := C.deserialize_compact_fhe_uint32(toBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint32 ciphertext deserialization failed")
		}
		var err error
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			return err
		}
	default:
		panic("deserializeCompact: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return nil
}

// Encrypts a value as a TFHE ciphertext, using the compact public FHE key.
// The resulting ciphertext is automaticaly expanded.
func (ct *tfheCiphertext) encrypt(value big.Int, t FheUintType) *tfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheUint8:
		ptr = C.public_key_encrypt_fhe_uint8(pks, C.uint8_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.public_key_encrypt_fhe_uint16(pks, C.uint16_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.public_key_encrypt_fhe_uint32(pks, C.uint32_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("encrypt: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return ct
}

func (ct *tfheCiphertext) trivialEncrypt(value big.Int, t FheUintType) *tfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheUint8:
		ptr = C.trivial_encrypt_fhe_uint8(sks, C.uint8_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.trivial_encrypt_fhe_uint16(sks, C.uint16_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.trivial_encrypt_fhe_uint32(sks, C.uint32_t(value.Uint64()))
		ct.serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("trivialEncrypt: unexpected ciphertext type")
	}
	ct.fheUintType = t
	ct.computeHash()
	return ct
}

func (ct *tfheCiphertext) serialize() []byte {
	return ct.serialization
}

func (ct *tfheCiphertext) executeUnaryCiphertextOperation(rhs *tfheCiphertext,
	op8 func(ct unsafe.Pointer) unsafe.Pointer,
	op16 func(ct unsafe.Pointer) unsafe.Pointer,
	op32 func(ct unsafe.Pointer) unsafe.Pointer) (*tfheCiphertext, error) {

	res := new(tfheCiphertext)
	res.fheUintType = ct.fheUintType
	res_ser := &C.Buffer{}
	switch ct.fheUintType {
	case FheUint8:
		ct_ptr := C.deserialize_fhe_uint8(toBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		res_ptr := op8(ct_ptr)
		C.destroy_fhe_uint8(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint16:
		ct_ptr := C.deserialize_fhe_uint16(toBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("16 bit unary op deserialization failed")
		}
		res_ptr := op16(ct_ptr)
		C.destroy_fhe_uint16(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint32:
		ct_ptr := C.deserialize_fhe_uint32(toBufferView((ct.serialization)))
		if ct_ptr == nil {
			return nil, errors.New("32 bit unary op deserialization failed")
		}
		res_ptr := op32(ct_ptr)
		C.destroy_fhe_uint32(ct_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit unary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	default:
		panic("unary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *tfheCiphertext) executeBinaryCiphertextOperation(rhs *tfheCiphertext,
	op8 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op16 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op32 func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer) (*tfheCiphertext, error) {
	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	res_ser := &C.Buffer{}
	switch lhs.fheUintType {
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint8(toBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint8(lhs_ptr)
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		res_ptr := op8(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint8(lhs_ptr)
		C.destroy_fhe_uint8(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint16(toBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint16(lhs_ptr)
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		res_ptr := op16(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint16(lhs_ptr)
		C.destroy_fhe_uint16(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		rhs_ptr := C.deserialize_fhe_uint32(toBufferView((rhs.serialization)))
		if rhs_ptr == nil {
			C.destroy_fhe_uint32(lhs_ptr)
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		res_ptr := op32(lhs_ptr, rhs_ptr)
		C.destroy_fhe_uint32(lhs_ptr)
		C.destroy_fhe_uint32(rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit binary op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	default:
		panic("binary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *tfheCiphertext) executeBinaryScalarOperation(rhs uint64,
	op8 func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer,
	op16 func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer,
	op32 func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer) (*tfheCiphertext, error) {
	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	res_ser := &C.Buffer{}
	switch lhs.fheUintType {
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit scalar op deserialization failed")
		}
		scalar := C.uint8_t(rhs)
		res_ptr := op8(lhs_ptr, scalar)
		C.destroy_fhe_uint8(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		C.destroy_fhe_uint8(res_ptr)
		if ret != 0 {
			return nil, errors.New("8 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit scalar op deserialization failed")
		}
		scalar := C.uint16_t(rhs)
		res_ptr := op16(lhs_ptr, scalar)
		C.destroy_fhe_uint16(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		C.destroy_fhe_uint16(res_ptr)
		if ret != 0 {
			return nil, errors.New("16 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toBufferView((lhs.serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit scalar op deserialization failed")
		}
		scalar := C.uint32_t(rhs)
		res_ptr := op32(lhs_ptr, scalar)
		C.destroy_fhe_uint32(lhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit scalar op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		C.destroy_fhe_uint32(res_ptr)
		if ret != 0 {
			return nil, errors.New("32 bit scalar op serialization failed")
		}
		res.serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_buffer(res_ser)
	default:
		panic("scalar op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *tfheCiphertext) add(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.add_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarAdd(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_add_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) sub(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.sub_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarSub(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_sub_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) mul(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.mul_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarMul(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_mul_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarDiv(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_div_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarRem(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_rem_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) bitand(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitand_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) bitor(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitor_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) bitxor(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.bitxor_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) shl(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shl_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarShl(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_shl_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) shr(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.shr_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarShr(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_shr_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) eq(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.eq_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarEq(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_eq_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) ne(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ne_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarNe(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_ne_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) ge(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.ge_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarGe(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_ge_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) gt(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.gt_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarGt(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_gt_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) le(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.le_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarLe(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_le_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) lt(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.lt_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarLt(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_lt_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) min(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.min_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarMin(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_min_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) max(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.max_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) scalarMax(rhs uint64) (*tfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		func(lhs unsafe.Pointer, rhs C.uint8_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint8(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint16(lhs, rhs, sks)
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) unsafe.Pointer {
			return C.scalar_max_fhe_uint32(lhs, rhs, sks)
		})
}

func (lhs *tfheCiphertext) neg() (*tfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint8(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint16(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.neg_fhe_uint32(lhs, sks)
		})
}

func (lhs *tfheCiphertext) not() (*tfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint8(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint16(lhs, sks)
		},
		func(lhs unsafe.Pointer) unsafe.Pointer {
			return C.not_fhe_uint32(lhs, sks)
		})
}

func (ct *tfheCiphertext) castTo(castToType FheUintType) (*tfheCiphertext, error) {
	if ct.fheUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	res := new(tfheCiphertext)
	res.fheUintType = castToType

	switch ct.fheUintType {
	case FheUint8:
		switch castToType {
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint8(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_16(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint16")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint8(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_32(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint32")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case FheUint16:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint16(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_8(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint8")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint16(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_32(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint32")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	case FheUint32:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint32(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_8(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint8")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint32(toBufferView(ct.serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_16(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint16")
			}
			var err error
			res.serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			panic("castTo: unexpected type to cast to")
		}
	}
	res.computeHash()
	return res, nil
}

func (ct *tfheCiphertext) decrypt() (big.Int, error) {
	var value uint64
	var ret C.int
	switch ct.fheUintType {
	case FheUint8:
		ptr := C.deserialize_fhe_uint8(toBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint8")
		}
		var result C.uint8_t
		ret = C.decrypt_fhe_uint8(cks, ptr, &result)
		C.destroy_fhe_uint8(ptr)
		value = uint64(result)
	case FheUint16:
		ptr := C.deserialize_fhe_uint16(toBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint16")
		}
		var result C.uint16_t
		ret = C.decrypt_fhe_uint16(cks, ptr, &result)
		C.destroy_fhe_uint16(ptr)
		value = uint64(result)
	case FheUint32:
		ptr := C.deserialize_fhe_uint32(toBufferView(ct.serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint32")
		}
		var result C.uint32_t
		ret = C.decrypt_fhe_uint32(cks, ptr, &result)
		C.destroy_fhe_uint32(ptr)
		value = uint64(result)
	default:
		panic("decrypt: unexpected ciphertext type")
	}
	if ret != 0 {
		return *new(big.Int).SetUint64(0), errors.New("decrypt failed")
	}
	return *new(big.Int).SetUint64(value), nil
}

func (ct *tfheCiphertext) computeHash() {
	hash := BytesToHash(Keccak256(ct.serialization))
	ct.hash = &hash
}

func (ct *tfheCiphertext) getHash() Hash {
	if ct.hash != nil {
		return *ct.hash
	}
	ct.computeHash()
	return *ct.hash
}

func isValidType(t byte) bool {
	if uint8(t) < uint8(FheUint8) || uint8(t) > uint8(FheUint32) {
		return false
	}
	return true
}

func encryptAndSerializeCompact(value uint32, fheUintType FheUintType) []byte {
	out := &C.Buffer{}
	switch fheUintType {
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ser
}
