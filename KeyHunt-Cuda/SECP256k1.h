/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <string>
#include <vector>

class Secp256K1
{

public:

	Secp256K1();
	~Secp256K1();
	void Init();
	Point ComputePublicKey(Int* privKey);
	Point NextKey(Point& key);
	void Check();
	bool  EC(Point& p);

	void GetHash160(bool compressed,
		Point& k0, Point& k1, Point& k2, Point& k3,
		uint8_t* h0, uint8_t* h1, uint8_t* h2, uint8_t* h3);

	void GetHash160(bool compressed, Point& pubKey, unsigned char* hash);
	void GetHashETH(Point& pubKey, unsigned char* hash);

	void GetPubKeyBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes);
	void GetXBytes(bool compressed, Point& pubKey, unsigned char* publicKeyBytes);

	std::string GetAddress(bool compressed, Point& pubKey);
	std::string GetAddressETH(Point& pubKey);
	std::string GetAddress(bool compressed, unsigned char* hash160);
	std::string GetAddressETH(unsigned char* hash);
	std::vector<std::string> GetAddress(bool compressed, unsigned char* h1, unsigned char* h2, unsigned char* h3, unsigned char* h4);
	std::string GetPrivAddress(bool compressed, Int& privKey);
	std::string GetPublicKeyHex(bool compressed, Point& pubKey);
	std::string GetPublicKeyHexETH(Point& pubKey);
	Point ParsePublicKeyHex(std::string str, bool& isCompressed);
	bool CheckPudAddress(std::string address);
	static Int DecodePrivateKey(char* key, bool* compressed);

	Point Add(Point& p1, Point& p2);
	Point Add2(Point& p1, Point& p2);
	Point AddDirect(Point& p1, Point& p2);
	Point Double(Point& p);
	Point DoubleDirect(Point& p);

	// *** НОВЫЕ МЕТОДЫ ДЛЯ MULTI-LAMBDA (ДОБАВЛЕНО) ***
	Point ApplyEndomorphism(Point& p, int lambda_id);
	static Int GetLambda(int id);
	Int GetLambda1() { return lambda1; }
	Int GetLambda2() { return lambda2; }
	Int GetLambda3() { return lambda3; }
	Int GetLambda4() { return lambda4; }

	Point G;                 // Generator
	Int   order;             // Curve order

private:

	uint8_t GetByte(std::string& str, int idx);

	Int GetY(Int x, bool isEven);
	Point GTable[256 * 32];     // Generator table

	// *** НОВЫЕ ЛЯМБДА-КОНСТАНТЫ (ДОБАВЛЕНО) ***
	Int lambda1;  // λ
	Int lambda2;  // λ²
	Int lambda3;  // λ³
	Int lambda4;  // λ⁻¹ (обратная)
};

#endif // SECP256K1H