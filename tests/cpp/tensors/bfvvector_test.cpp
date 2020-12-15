#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tenseal/cpp/tenseal.h"

namespace tenseal {
namespace {
using namespace ::testing;
using namespace std;

auto duplicate(shared_ptr<BFVVector> in) {
    auto vec = in->save();
    return BFVVector::Create(in->tenseal_context(), vec);
}

class BFVVectorTest : public TestWithParam</*serialize=*/bool> {
   protected:
    void SetUp() {}
};

TEST_P(BFVVectorTest, TestCreateBFV) {
    bool should_serialize_first = GetParam();

    auto ctx = TenSEALContext::Create(scheme_type::bfv, 8192, 1032193, {});
    ASSERT_TRUE(ctx != nullptr);

    auto l = BFVVector::Create(ctx, vector<int64_t>({1, 2, 3}));

    if (should_serialize_first) {
        l = duplicate(l);
    }

    ASSERT_EQ(l->size(), 3);
    ASSERT_EQ(l->ciphertext_size(), 2);
}

TEST_P(BFVVectorTest, TestBFVAdd) {
    bool should_serialize_first = GetParam();

    auto ctx = TenSEALContext::Create(scheme_type::bfv, 8192, 1032193, {});
    ASSERT_TRUE(ctx != nullptr);

    auto l = BFVVector::Create(ctx, vector<int64_t>({1, 2, 3}));
    auto r = BFVVector::Create(ctx, vector<int64_t>({2, 3, 4}));

    auto add = l->add(r);
    ASSERT_EQ(add->ciphertext_size(), 2);

    auto decr = add->decrypt();
    EXPECT_THAT(decr.data(), ElementsAreArray({3, 5, 7}));

    l->add_inplace(r);
    l->add_inplace(r);
    l->add_inplace(r);
    l->add_inplace(r);

    if (should_serialize_first) {
        l = duplicate(l);
    }

    ASSERT_EQ(l->ciphertext_size(), 2);
    decr = l->decrypt();
    EXPECT_THAT(decr.data(), ElementsAreArray({9, 14, 19}));
}

TEST_P(BFVVectorTest, TestBFVMul) {
    bool should_serialize_first = GetParam();

    auto ctx = TenSEALContext::Create(scheme_type::bfv, 8192, 1032193, {});
    ASSERT_TRUE(ctx != nullptr);

    auto l = BFVVector::Create(ctx, vector<int64_t>({1, 2, 3}));
    auto r = BFVVector::Create(ctx, vector<int64_t>({2, 3, 4}));

    auto mul = l->mul(r);
    ASSERT_EQ(mul->ciphertext_size(), 2);

    auto decr = mul->decrypt();
    EXPECT_THAT(decr.data(), ElementsAreArray({2, 6, 12}));

    r = BFVVector::Create(ctx, vector<int64_t>({2, 2, 2}));

    l->mul_inplace(r);
    l->mul_inplace(r);
    l->mul_inplace(r);
    l->mul_inplace(r);

    if (should_serialize_first) {
        l = duplicate(l);
    }

    ASSERT_EQ(l->ciphertext_size(), 2);

    decr = l->decrypt();
    EXPECT_THAT(decr.data(), ElementsAreArray({16, 32, 48}));
}

TEST_P(BFVVectorTest, TestEmptyPlaintext) {
    auto ctx = TenSEALContext::Create(scheme_type::bfv, 8192, 1032193, {});
    ASSERT_TRUE(ctx != nullptr);

    EXPECT_THROW(BFVVector::Create(ctx, std::vector<int64_t>({})),
                 std::exception);
}

void replicate(vector<int64_t>& data, size_t times) {
    size_t init_size = data.size();
    data.reserve(times);
    for (size_t i = 0; i < times - init_size; i++) {
        data.push_back(data[i % init_size]);
    }
}

vector<int64_t> decrypt(Decryptor& decryptor, BatchEncoder& encoder,
                        const Ciphertext& ct) {
    vector<int64_t> result;
    Plaintext plaintext;

    decryptor.decrypt(ct, plaintext);
    encoder.decode(plaintext, result);

    return result;
}

TEST_F(BFVVectorTest, TestContextRegressionNoise) {
    EncryptionParameters parameters(scheme_type::bfv);
    parameters.set_poly_modulus_degree(4096);
    parameters.set_plain_modulus(1032193);
    parameters.set_coeff_modulus(CoeffModulus::BFVDefault(4096));

    auto ctx = SEALContext(parameters);
    auto keygen = KeyGenerator(ctx);
    auto sk = SecretKey(keygen.secret_key());

    PublicKey pk;
    keygen.create_public_key(pk);

    auto encryptor = Encryptor(ctx, pk);
    auto decryptor = Decryptor(ctx, sk);
    auto encoder = BatchEncoder(ctx);
    auto evaluator = Evaluator(ctx);

    vector<int64_t> data = {2};
    replicate(data, encoder.slot_count());

    Ciphertext initial(ctx);
    Plaintext plaintext;

    encoder.encode(data, plaintext);
    encryptor.encrypt(plaintext, initial);

    auto test_mul = initial;
    auto expected = 2;

    auto dec = decrypt(decryptor, encoder, test_mul);
    ASSERT_EQ(dec[0], expected);

    for (int step = 0; step < 2; ++step) {
        expected *= 2;
        evaluator.multiply_inplace(test_mul, initial);

        auto dec = decrypt(decryptor, encoder, test_mul);
        ASSERT_EQ(dec[0], expected);
    }
}

INSTANTIATE_TEST_CASE_P(TestBFVVector, BFVVectorTest,
                        ::testing::Values(false, true));

}  // namespace
}  // namespace tenseal
