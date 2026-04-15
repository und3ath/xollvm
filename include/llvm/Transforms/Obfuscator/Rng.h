#pragma once
#include <cstdint>
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

namespace llvm::obf {

	// ---------- stable hash (FNV-1a 64) ----------
	inline uint64_t fnv1a64(llvm::StringRef S) {
		uint64_t H = 14695981039346656037ull;
		for (unsigned char C : S) {
			H ^= (uint64_t)C;
			H *= 1099511628211ull;
		}
		return H;
	}

	// ---------- SplitMix64 mixing ----------
	inline uint64_t mix64(uint64_t X) {
		X += 0x9e3779b97f4a7c15ull;
		X = (X ^ (X >> 30)) * 0xbf58476d1ce4e5b9ull;
		X = (X ^ (X >> 27)) * 0x94d049bb133111ebull;
		return X ^ (X >> 31);
	}

	// ---------- xoshiro256++ ----------
	class Rng {
		uint64_t S[4];
		uint64_t SeedBase; // <- stable base for fork()

		static inline uint64_t rotl(uint64_t X, int K) {
			return (X << K) | (X >> (64 - K));
		}
		static inline uint64_t splitmix64_next(uint64_t& X) {
			X += 0x9e3779b97f4a7c15ull;
			uint64_t Z = X;
			Z = (Z ^ (Z >> 30)) * 0xbf58476d1ce4e5b9ull;
			Z = (Z ^ (Z >> 27)) * 0x94d049bb133111ebull;
			return Z ^ (Z >> 31);
		}

	public:
		explicit Rng(uint64_t Seed = 0) : SeedBase(Seed) {
			uint64_t X = Seed;
			S[0] = splitmix64_next(X);
			S[1] = splitmix64_next(X);
			S[2] = splitmix64_next(X);
			S[3] = splitmix64_next(X);
		}

		uint64_t baseSeed() const { return SeedBase; }

		uint64_t u64() {
			const uint64_t Result = rotl(S[0] + S[3], 23) + S[0];
			const uint64_t T = S[1] << 17;
			S[2] ^= S[0];
			S[3] ^= S[1];
			S[1] ^= S[2];
			S[0] ^= S[3];
			S[2] ^= T;
			S[3] = rotl(S[3], 45);
			return Result;
		}

		uint32_t u32() { return (uint32_t)u64(); }

		// unbiased bounded [0, bound-1] (Lemire)
		uint32_t range(uint32_t Bound) {
			if (Bound == 0) return 0;
			for (;;) {
				uint32_t X = u32();
				uint64_t M = (uint64_t)X * (uint64_t)Bound;
				uint32_t L = (uint32_t)M;
				if (L >= Bound) return (uint32_t)(M >> 32);
				uint32_t T = (uint32_t)(-Bound) % Bound;
				if (L >= T) return (uint32_t)(M >> 32);
			}
		}

		void bytes(llvm::MutableArrayRef<uint8_t> Out) {
			size_t I = 0;
			while (I < Out.size()) {
				uint64_t X = u64();
				for (int k = 0; k < 8 && I < Out.size(); ++k, ++I) {
					Out[I] = (uint8_t)(X & 0xff);
					X >>= 8;
				}
			}
		}

		template <typename T>
		void shuffle(llvm::MutableArrayRef<T> A) {
			for (size_t I = A.size(); I > 1; --I) {
				size_t J = (size_t)range((uint32_t)I);
				T Tmp = A[I - 1];
				A[I - 1] = A[J];
				A[J] = Tmp;
			}
		}

		// ---- fork() that DOES NOT depend on parent consumption ----
		uint64_t forkSeed(llvm::StringRef Label) const {
			// Make fork seeds stable under future added RNG draws:
			// only depends on construction seed + label.
			return mix64(SeedBase ^ fnv1a64(Label) ^ 0xA5A5A5A5D1B54A32ull);
		}

		Rng fork(llvm::StringRef Label) const { return Rng(forkSeed(Label)); }

		uint64_t forkSeed(uint64_t Tag) const {
			return mix64(SeedBase ^ mix64(Tag) ^ 0xC3A5C85C97CB3127ull);
		}

		Rng fork(uint64_t Tag) const { return Rng(forkSeed(Tag)); }
	};

} // namespace llvm::obf
