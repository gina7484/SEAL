#include "mult.h"
#include <ittnotify.h>
#include <omp.h>

#define xencrypt( n ) x##n##_encrypted

using namespace std;
using namespace seal;

int main()
{
    __itt_pause();
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    
    size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

    print_example_banner("CKKS Performance Test: Mult");

    // It is not recommended to use BFVDefault primes in CKKS. However, for performance
    // test, BFVDefault primes are good enough.
    EncryptionParameters parms(scheme_type::ckks);
    
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /*
    [Key Generation]
    */
    cout << "Generating secret/public keys: ";
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    cout << "Done" << endl;

    cout << "Generating relinearize keys: ";
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    cout << "Done" << endl;

    cout << "Generating Galois keys: ";
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    cout << "Done" << endl;

    /*
    [Encryptor, Decryptor, Evaluator, Encoder]
    */
    cout << "Set up Encryptor, Decryptor, Evaluator, Encoder";
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    cout << "Done" << endl;

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /*
    [Encode & Encryption]
    */
    cout << "Generate input1" << endl;
    vector<double> input1;
    input1.reserve(slot_count);
    double curr_point = 0;
    double step_size1 = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input1.push_back(curr_point);
        curr_point += step_size1;
    }
    cout << "    Input vector1: " << endl;
    print_vector(input1, 5, 7);
    // input1 = [0, 1/4095, 2/4095, 3/4095, ... 4094/4095, 4095/4095]

    cout << "Encode input vectors." << endl;
    Plaintext x1_plain;
    encoder.encode(input1, scale, x1_plain);

    Ciphertext x1_encrypted, x2_encrypted, x3_encrypted, x4_encrypted;
    Ciphertext x5_encrypted, x6_encrypted, x7_encrypted, x8_encrypted;
    Ciphertext x9_encrypted, x10_encrypted, x11_encrypted, x12_encrypted;
    Ciphertext x13_encrypted, x14_encrypted, x15_encrypted, x16_encrypted;
    Ciphertext x17_encrypted, x18_encrypted, x19_encrypted, x20_encrypted;
    Ciphertext x21_encrypted, x22_encrypted, x23_encrypted, x24_encrypted;
    Ciphertext x25_encrypted, x26_encrypted, x27_encrypted, x28_encrypted;
    Ciphertext x29_encrypted, x30_encrypted, x31_encrypted;
    Ciphertext x32_encrypted, x33_encrypted, x34_encrypted, x35_encrypted;
    Ciphertext x36_encrypted, x37_encrypted, x38_encrypted, x39_encrypted;
    Ciphertext x40_encrypted, x41_encrypted, x42_encrypted, x43_encrypted;
    Ciphertext x44_encrypted, x45_encrypted, x46_encrypted, x47_encrypted;
    Ciphertext x48_encrypted, x49_encrypted, x50_encrypted, x51_encrypted;
    Ciphertext x52_encrypted, x53_encrypted, x54_encrypted, x55_encrypted;
    Ciphertext x56_encrypted, x57_encrypted, x58_encrypted, x59_encrypted;
    Ciphertext x60_encrypted, x61_encrypted, x62_encrypted, x63_encrypted;
    Ciphertext x64_encrypted, x65_encrypted, x66_encrypted, x67_encrypted;
    Ciphertext x68_encrypted, x69_encrypted, x70_encrypted, x71_encrypted;
    Ciphertext x72_encrypted, x73_encrypted, x74_encrypted, x75_encrypted;
    Ciphertext x76_encrypted, x77_encrypted, x78_encrypted, x79_encrypted;
    Ciphertext x80_encrypted, x81_encrypted, x82_encrypted, x83_encrypted;
    Ciphertext x84_encrypted, x85_encrypted, x86_encrypted, x87_encrypted;
    Ciphertext x88_encrypted, x89_encrypted, x90_encrypted, x91_encrypted;
    Ciphertext x92_encrypted, x93_encrypted, x94_encrypted, x95_encrypted;
    Ciphertext x96_encrypted, x97_encrypted, x98_encrypted, x99_encrypted;
    Ciphertext x100_encrypted;
    Ciphertext x101_encrypted, x102_encrypted, x103_encrypted, x104_encrypted;
    Ciphertext x105_encrypted, x106_encrypted, x107_encrypted, x108_encrypted;
    Ciphertext x109_encrypted, x110_encrypted, x111_encrypted, x112_encrypted;
    Ciphertext x113_encrypted, x114_encrypted, x115_encrypted, x116_encrypted;
    Ciphertext x117_encrypted, x118_encrypted, x119_encrypted, x120_encrypted;
    Ciphertext x121_encrypted, x122_encrypted, x123_encrypted, x124_encrypted;
    Ciphertext x125_encrypted, x126_encrypted, x127_encrypted, x128_encrypted;
    Ciphertext x129_encrypted, x130_encrypted, x131_encrypted, x132_encrypted;
    Ciphertext x133_encrypted, x134_encrypted, x135_encrypted, x136_encrypted;
    Ciphertext x137_encrypted, x138_encrypted, x139_encrypted, x140_encrypted;
    Ciphertext x141_encrypted, x142_encrypted, x143_encrypted, x144_encrypted;
    Ciphertext x145_encrypted, x146_encrypted, x147_encrypted, x148_encrypted;
    Ciphertext x149_encrypted, x150_encrypted, x151_encrypted, x152_encrypted;
    Ciphertext x153_encrypted, x154_encrypted, x155_encrypted, x156_encrypted;
    Ciphertext x157_encrypted, x158_encrypted, x159_encrypted, x160_encrypted;
    Ciphertext x161_encrypted, x162_encrypted, x163_encrypted, x164_encrypted;
    Ciphertext x165_encrypted, x166_encrypted, x167_encrypted, x168_encrypted;
    Ciphertext x169_encrypted, x170_encrypted, x171_encrypted, x172_encrypted;
    Ciphertext x173_encrypted, x174_encrypted, x175_encrypted, x176_encrypted;
    Ciphertext x177_encrypted, x178_encrypted, x179_encrypted, x180_encrypted;
    Ciphertext x181_encrypted, x182_encrypted, x183_encrypted, x184_encrypted;
    Ciphertext x185_encrypted, x186_encrypted, x187_encrypted, x188_encrypted;
    Ciphertext x189_encrypted, x190_encrypted, x191_encrypted, x192_encrypted;
    Ciphertext x193_encrypted, x194_encrypted, x195_encrypted, x196_encrypted;
    Ciphertext x197_encrypted, x198_encrypted, x199_encrypted, x200_encrypted;
    Ciphertext x201_encrypted, x202_encrypted, x203_encrypted, x204_encrypted;
    Ciphertext x205_encrypted, x206_encrypted, x207_encrypted, x208_encrypted;
    Ciphertext x209_encrypted, x210_encrypted, x211_encrypted, x212_encrypted;
    Ciphertext x213_encrypted, x214_encrypted, x215_encrypted, x216_encrypted;
    Ciphertext x217_encrypted, x218_encrypted, x219_encrypted, x220_encrypted;
    Ciphertext x221_encrypted, x222_encrypted, x223_encrypted, x224_encrypted;
    Ciphertext x225_encrypted, x226_encrypted, x227_encrypted, x228_encrypted;
    Ciphertext x229_encrypted, x230_encrypted, x231_encrypted, x232_encrypted;
    Ciphertext x233_encrypted, x234_encrypted, x235_encrypted, x236_encrypted;
    Ciphertext x237_encrypted, x238_encrypted, x239_encrypted, x240_encrypted;
    Ciphertext x241_encrypted, x242_encrypted, x243_encrypted, x244_encrypted;
    Ciphertext x245_encrypted, x246_encrypted, x247_encrypted, x248_encrypted;
    Ciphertext x249_encrypted, x250_encrypted, x251_encrypted, x252_encrypted;
    Ciphertext x253_encrypted, x254_encrypted, x255_encrypted, x256_encrypted;
    
    
    vector<Ciphertext> encrypteds_vec;
    encrypteds_vec.reserve(256); // x1_encrypted ~ x256_encrypted
    
    encryptor.encrypt(x1_plain, x1_encrypted);
    encrypteds_vec.emplace_back(x1_encrypted);
    
    encryptor.encrypt(x1_plain, x2_encrypted);
    encrypteds_vec.emplace_back(x2_encrypted);

    encryptor.encrypt(x1_plain, x3_encrypted);
    encrypteds_vec.emplace_back(x3_encrypted);

    encryptor.encrypt(x1_plain, x4_encrypted);
    encrypteds_vec.emplace_back(x4_encrypted);

    encryptor.encrypt(x1_plain, x5_encrypted);
    encrypteds_vec.emplace_back(x5_encrypted);

    encryptor.encrypt(x1_plain, x6_encrypted);
    encrypteds_vec.emplace_back(x6_encrypted);

    encryptor.encrypt(x1_plain, x7_encrypted);
    encrypteds_vec.emplace_back(x7_encrypted);

    encryptor.encrypt(x1_plain, x8_encrypted);
    encrypteds_vec.emplace_back(x8_encrypted);

    encryptor.encrypt(x1_plain, x9_encrypted);
    encrypteds_vec.emplace_back(x9_encrypted);

    encryptor.encrypt(x1_plain, x10_encrypted);
    encrypteds_vec.emplace_back(x10_encrypted);

    encryptor.encrypt(x1_plain, x11_encrypted);
    encrypteds_vec.emplace_back(x11_encrypted);

    encryptor.encrypt(x1_plain, x12_encrypted);
    encrypteds_vec.emplace_back(x12_encrypted);

    encryptor.encrypt(x1_plain, x13_encrypted);
    encrypteds_vec.emplace_back(x13_encrypted);

    encryptor.encrypt(x1_plain, x14_encrypted);
    encrypteds_vec.emplace_back(x14_encrypted);

    encryptor.encrypt(x1_plain, x15_encrypted);
    encrypteds_vec.emplace_back(x15_encrypted);

    encryptor.encrypt(x1_plain, x16_encrypted);
    encrypteds_vec.emplace_back(x16_encrypted);

    encryptor.encrypt(x1_plain, x17_encrypted);
    encrypteds_vec.emplace_back(x17_encrypted);

    encryptor.encrypt(x1_plain, x18_encrypted);
    encrypteds_vec.emplace_back(x18_encrypted);

    encryptor.encrypt(x1_plain, x19_encrypted);
    encrypteds_vec.emplace_back(x19_encrypted);

    encryptor.encrypt(x1_plain, x20_encrypted);
    encrypteds_vec.emplace_back(x20_encrypted);

    encryptor.encrypt(x1_plain, x21_encrypted);
    encrypteds_vec.emplace_back(x21_encrypted);

    encryptor.encrypt(x1_plain, x22_encrypted);
    encrypteds_vec.emplace_back(x22_encrypted);

    encryptor.encrypt(x1_plain, x23_encrypted);
    encrypteds_vec.emplace_back(x23_encrypted);

    encryptor.encrypt(x1_plain, x24_encrypted);
    encrypteds_vec.emplace_back(x24_encrypted);

    encryptor.encrypt(x1_plain, x25_encrypted);
    encrypteds_vec.emplace_back(x25_encrypted);

    encryptor.encrypt(x1_plain, x26_encrypted);
    encrypteds_vec.emplace_back(x26_encrypted);

    encryptor.encrypt(x1_plain, x27_encrypted);
    encrypteds_vec.emplace_back(x27_encrypted);

    encryptor.encrypt(x1_plain, x28_encrypted);
    encrypteds_vec.emplace_back(x28_encrypted);

    encryptor.encrypt(x1_plain, x29_encrypted);
    encrypteds_vec.emplace_back(x29_encrypted);

    encryptor.encrypt(x1_plain, x30_encrypted);
    encrypteds_vec.emplace_back(x30_encrypted);

    encryptor.encrypt(x1_plain, x31_encrypted);
    encrypteds_vec.emplace_back(x31_encrypted);

    encryptor.encrypt(x1_plain, x32_encrypted);
    encrypteds_vec.emplace_back(x32_encrypted);

    encryptor.encrypt(x1_plain, x33_encrypted);
    encrypteds_vec.emplace_back(x33_encrypted);

    encryptor.encrypt(x1_plain, x34_encrypted);
    encrypteds_vec.emplace_back(x34_encrypted);

    encryptor.encrypt(x1_plain, x35_encrypted);
    encrypteds_vec.emplace_back(x35_encrypted);

    encryptor.encrypt(x1_plain, x36_encrypted);
    encrypteds_vec.emplace_back(x36_encrypted);

    encryptor.encrypt(x1_plain, x37_encrypted);
    encrypteds_vec.emplace_back(x37_encrypted);

    encryptor.encrypt(x1_plain, x38_encrypted);
    encrypteds_vec.emplace_back(x38_encrypted);

    encryptor.encrypt(x1_plain, x39_encrypted);
    encrypteds_vec.emplace_back(x39_encrypted);

    encryptor.encrypt(x1_plain, x40_encrypted);
    encrypteds_vec.emplace_back(x40_encrypted);

    encryptor.encrypt(x1_plain, x41_encrypted);
    encrypteds_vec.emplace_back(x41_encrypted);

    encryptor.encrypt(x1_plain, x42_encrypted);
    encrypteds_vec.emplace_back(x42_encrypted);

    encryptor.encrypt(x1_plain, x43_encrypted);
    encrypteds_vec.emplace_back(x43_encrypted);

    encryptor.encrypt(x1_plain, x44_encrypted);
    encrypteds_vec.emplace_back(x44_encrypted);

    encryptor.encrypt(x1_plain, x45_encrypted);
    encrypteds_vec.emplace_back(x45_encrypted);

    encryptor.encrypt(x1_plain, x46_encrypted);
    encrypteds_vec.emplace_back(x46_encrypted);

    encryptor.encrypt(x1_plain, x47_encrypted);
    encrypteds_vec.emplace_back(x47_encrypted);

    encryptor.encrypt(x1_plain, x48_encrypted);
    encrypteds_vec.emplace_back(x48_encrypted);

    encryptor.encrypt(x1_plain, x49_encrypted);
    encrypteds_vec.emplace_back(x49_encrypted);

    encryptor.encrypt(x1_plain, x50_encrypted);
    encrypteds_vec.emplace_back(x50_encrypted);

    encryptor.encrypt(x1_plain, x51_encrypted);
    encrypteds_vec.emplace_back(x51_encrypted);

    encryptor.encrypt(x1_plain, x52_encrypted);
    encrypteds_vec.emplace_back(x52_encrypted);

    encryptor.encrypt(x1_plain, x53_encrypted);
    encrypteds_vec.emplace_back(x53_encrypted);

    encryptor.encrypt(x1_plain, x54_encrypted);
    encrypteds_vec.emplace_back(x54_encrypted);

    encryptor.encrypt(x1_plain, x55_encrypted);
    encrypteds_vec.emplace_back(x55_encrypted);

    encryptor.encrypt(x1_plain, x56_encrypted);
    encrypteds_vec.emplace_back(x56_encrypted);

    encryptor.encrypt(x1_plain, x57_encrypted);
    encrypteds_vec.emplace_back(x57_encrypted);

    encryptor.encrypt(x1_plain, x58_encrypted);
    encrypteds_vec.emplace_back(x58_encrypted);

    encryptor.encrypt(x1_plain, x59_encrypted);
    encrypteds_vec.emplace_back(x59_encrypted);

    encryptor.encrypt(x1_plain, x60_encrypted);
    encrypteds_vec.emplace_back(x60_encrypted);

    encryptor.encrypt(x1_plain, x61_encrypted);
    encrypteds_vec.emplace_back(x61_encrypted);

    encryptor.encrypt(x1_plain, x62_encrypted);
    encrypteds_vec.emplace_back(x62_encrypted);

    encryptor.encrypt(x1_plain, x63_encrypted);
    encrypteds_vec.emplace_back(x63_encrypted);

    encryptor.encrypt(x1_plain, x64_encrypted);
    encrypteds_vec.emplace_back(x64_encrypted);

    encryptor.encrypt(x1_plain, x65_encrypted);
    encrypteds_vec.emplace_back(x65_encrypted);

    encryptor.encrypt(x1_plain, x66_encrypted);
    encrypteds_vec.emplace_back(x66_encrypted);

    encryptor.encrypt(x1_plain, x67_encrypted);
    encrypteds_vec.emplace_back(x67_encrypted);

    encryptor.encrypt(x1_plain, x68_encrypted);
    encrypteds_vec.emplace_back(x68_encrypted);

    encryptor.encrypt(x1_plain, x69_encrypted);
    encrypteds_vec.emplace_back(x69_encrypted);

    encryptor.encrypt(x1_plain, x70_encrypted);
    encrypteds_vec.emplace_back(x70_encrypted);

    encryptor.encrypt(x1_plain, x71_encrypted);
    encrypteds_vec.emplace_back(x71_encrypted);

    encryptor.encrypt(x1_plain, x72_encrypted);
    encrypteds_vec.emplace_back(x72_encrypted);

    encryptor.encrypt(x1_plain, x73_encrypted);
    encrypteds_vec.emplace_back(x73_encrypted);

    encryptor.encrypt(x1_plain, x74_encrypted);
    encrypteds_vec.emplace_back(x74_encrypted);

    encryptor.encrypt(x1_plain, x75_encrypted);
    encrypteds_vec.emplace_back(x75_encrypted);

    encryptor.encrypt(x1_plain, x76_encrypted);
    encrypteds_vec.emplace_back(x76_encrypted);

    encryptor.encrypt(x1_plain, x77_encrypted);
    encrypteds_vec.emplace_back(x77_encrypted);

    encryptor.encrypt(x1_plain, x78_encrypted);
    encrypteds_vec.emplace_back(x78_encrypted);

    encryptor.encrypt(x1_plain, x79_encrypted);
    encrypteds_vec.emplace_back(x79_encrypted);

    encryptor.encrypt(x1_plain, x80_encrypted);
    encrypteds_vec.emplace_back(x80_encrypted);

    encryptor.encrypt(x1_plain, x81_encrypted);
    encrypteds_vec.emplace_back(x81_encrypted);

    encryptor.encrypt(x1_plain, x82_encrypted);
    encrypteds_vec.emplace_back(x82_encrypted);

    encryptor.encrypt(x1_plain, x83_encrypted);
    encrypteds_vec.emplace_back(x83_encrypted);

    encryptor.encrypt(x1_plain, x84_encrypted);
    encrypteds_vec.emplace_back(x84_encrypted);

    encryptor.encrypt(x1_plain, x85_encrypted);
    encrypteds_vec.emplace_back(x85_encrypted);

    encryptor.encrypt(x1_plain, x86_encrypted);
    encrypteds_vec.emplace_back(x86_encrypted);

    encryptor.encrypt(x1_plain, x87_encrypted);
    encrypteds_vec.emplace_back(x87_encrypted);

    encryptor.encrypt(x1_plain, x88_encrypted);
    encrypteds_vec.emplace_back(x88_encrypted);

    encryptor.encrypt(x1_plain, x89_encrypted);
    encrypteds_vec.emplace_back(x89_encrypted);

    encryptor.encrypt(x1_plain, x90_encrypted);
    encrypteds_vec.emplace_back(x90_encrypted);

    encryptor.encrypt(x1_plain, x91_encrypted);
    encrypteds_vec.emplace_back(x91_encrypted);

    encryptor.encrypt(x1_plain, x92_encrypted);
    encrypteds_vec.emplace_back(x92_encrypted);

    encryptor.encrypt(x1_plain, x93_encrypted);
    encrypteds_vec.emplace_back(x93_encrypted);

    encryptor.encrypt(x1_plain, x94_encrypted);
    encrypteds_vec.emplace_back(x94_encrypted);

    encryptor.encrypt(x1_plain, x95_encrypted);
    encrypteds_vec.emplace_back(x95_encrypted);

    encryptor.encrypt(x1_plain, x96_encrypted);
    encrypteds_vec.emplace_back(x96_encrypted);

    encryptor.encrypt(x1_plain, x97_encrypted);
    encrypteds_vec.emplace_back(x97_encrypted);

    encryptor.encrypt(x1_plain, x98_encrypted);
    encrypteds_vec.emplace_back(x98_encrypted);

    encryptor.encrypt(x1_plain, x99_encrypted);
    encrypteds_vec.emplace_back(x99_encrypted);

    encryptor.encrypt(x1_plain, x100_encrypted);
    encrypteds_vec.emplace_back(x100_encrypted);
    
    encryptor.encrypt(x1_plain, x101_encrypted);
    encrypteds_vec.emplace_back(x101_encrypted);

    encryptor.encrypt(x1_plain, x102_encrypted);
    encrypteds_vec.emplace_back(x102_encrypted);

    encryptor.encrypt(x1_plain, x103_encrypted);
    encrypteds_vec.emplace_back(x103_encrypted);

    encryptor.encrypt(x1_plain, x104_encrypted);
    encrypteds_vec.emplace_back(x104_encrypted);

    encryptor.encrypt(x1_plain, x105_encrypted);
    encrypteds_vec.emplace_back(x105_encrypted);

    encryptor.encrypt(x1_plain, x106_encrypted);
    encrypteds_vec.emplace_back(x106_encrypted);

    encryptor.encrypt(x1_plain, x107_encrypted);
    encrypteds_vec.emplace_back(x107_encrypted);

    encryptor.encrypt(x1_plain, x108_encrypted);
    encrypteds_vec.emplace_back(x108_encrypted);

    encryptor.encrypt(x1_plain, x109_encrypted);
    encrypteds_vec.emplace_back(x109_encrypted);

    encryptor.encrypt(x1_plain, x110_encrypted);
    encrypteds_vec.emplace_back(x110_encrypted);

    encryptor.encrypt(x1_plain, x111_encrypted);
    encrypteds_vec.emplace_back(x111_encrypted);

    encryptor.encrypt(x1_plain, x112_encrypted);
    encrypteds_vec.emplace_back(x112_encrypted);

    encryptor.encrypt(x1_plain, x113_encrypted);
    encrypteds_vec.emplace_back(x113_encrypted);

    encryptor.encrypt(x1_plain, x114_encrypted);
    encrypteds_vec.emplace_back(x114_encrypted);

    encryptor.encrypt(x1_plain, x115_encrypted);
    encrypteds_vec.emplace_back(x115_encrypted);

    encryptor.encrypt(x1_plain, x116_encrypted);
    encrypteds_vec.emplace_back(x116_encrypted);

    encryptor.encrypt(x1_plain, x117_encrypted);
    encrypteds_vec.emplace_back(x117_encrypted);

    encryptor.encrypt(x1_plain, x118_encrypted);
    encrypteds_vec.emplace_back(x118_encrypted);

    encryptor.encrypt(x1_plain, x119_encrypted);
    encrypteds_vec.emplace_back(x119_encrypted);

    encryptor.encrypt(x1_plain, x120_encrypted);
    encrypteds_vec.emplace_back(x120_encrypted);

    encryptor.encrypt(x1_plain, x121_encrypted);
    encrypteds_vec.emplace_back(x121_encrypted);

    encryptor.encrypt(x1_plain, x122_encrypted);
    encrypteds_vec.emplace_back(x122_encrypted);

    encryptor.encrypt(x1_plain, x123_encrypted);
    encrypteds_vec.emplace_back(x123_encrypted);

    encryptor.encrypt(x1_plain, x124_encrypted);
    encrypteds_vec.emplace_back(x124_encrypted);

    encryptor.encrypt(x1_plain, x125_encrypted);
    encrypteds_vec.emplace_back(x125_encrypted);

    encryptor.encrypt(x1_plain, x126_encrypted);
    encrypteds_vec.emplace_back(x126_encrypted);

    encryptor.encrypt(x1_plain, x127_encrypted);
    encrypteds_vec.emplace_back(x127_encrypted);

    encryptor.encrypt(x1_plain, x128_encrypted);
    encrypteds_vec.emplace_back(x128_encrypted);

    encryptor.encrypt(x1_plain, x129_encrypted);
    encrypteds_vec.emplace_back(x129_encrypted);

    encryptor.encrypt(x1_plain, x130_encrypted);
    encrypteds_vec.emplace_back(x130_encrypted);

    encryptor.encrypt(x1_plain, x131_encrypted);
    encrypteds_vec.emplace_back(x131_encrypted);

    encryptor.encrypt(x1_plain, x132_encrypted);
    encrypteds_vec.emplace_back(x132_encrypted);

    encryptor.encrypt(x1_plain, x133_encrypted);
    encrypteds_vec.emplace_back(x133_encrypted);

    encryptor.encrypt(x1_plain, x134_encrypted);
    encrypteds_vec.emplace_back(x134_encrypted);

    encryptor.encrypt(x1_plain, x135_encrypted);
    encrypteds_vec.emplace_back(x135_encrypted);

    encryptor.encrypt(x1_plain, x136_encrypted);
    encrypteds_vec.emplace_back(x136_encrypted);

    encryptor.encrypt(x1_plain, x137_encrypted);
    encrypteds_vec.emplace_back(x137_encrypted);

    encryptor.encrypt(x1_plain, x138_encrypted);
    encrypteds_vec.emplace_back(x138_encrypted);

    encryptor.encrypt(x1_plain, x139_encrypted);
    encrypteds_vec.emplace_back(x139_encrypted);

    encryptor.encrypt(x1_plain, x140_encrypted);
    encrypteds_vec.emplace_back(x140_encrypted);

    encryptor.encrypt(x1_plain, x141_encrypted);
    encrypteds_vec.emplace_back(x141_encrypted);

    encryptor.encrypt(x1_plain, x142_encrypted);
    encrypteds_vec.emplace_back(x142_encrypted);

    encryptor.encrypt(x1_plain, x143_encrypted);
    encrypteds_vec.emplace_back(x143_encrypted);

    encryptor.encrypt(x1_plain, x144_encrypted);
    encrypteds_vec.emplace_back(x144_encrypted);

    encryptor.encrypt(x1_plain, x145_encrypted);
    encrypteds_vec.emplace_back(x145_encrypted);

    encryptor.encrypt(x1_plain, x146_encrypted);
    encrypteds_vec.emplace_back(x146_encrypted);

    encryptor.encrypt(x1_plain, x147_encrypted);
    encrypteds_vec.emplace_back(x147_encrypted);

    encryptor.encrypt(x1_plain, x148_encrypted);
    encrypteds_vec.emplace_back(x148_encrypted);

    encryptor.encrypt(x1_plain, x149_encrypted);
    encrypteds_vec.emplace_back(x149_encrypted);

    encryptor.encrypt(x1_plain, x150_encrypted);
    encrypteds_vec.emplace_back(x150_encrypted);

    encryptor.encrypt(x1_plain, x151_encrypted);
    encrypteds_vec.emplace_back(x151_encrypted);

    encryptor.encrypt(x1_plain, x152_encrypted);
    encrypteds_vec.emplace_back(x152_encrypted);

    encryptor.encrypt(x1_plain, x153_encrypted);
    encrypteds_vec.emplace_back(x153_encrypted);

    encryptor.encrypt(x1_plain, x154_encrypted);
    encrypteds_vec.emplace_back(x154_encrypted);

    encryptor.encrypt(x1_plain, x155_encrypted);
    encrypteds_vec.emplace_back(x155_encrypted);

    encryptor.encrypt(x1_plain, x156_encrypted);
    encrypteds_vec.emplace_back(x156_encrypted);

    encryptor.encrypt(x1_plain, x157_encrypted);
    encrypteds_vec.emplace_back(x157_encrypted);

    encryptor.encrypt(x1_plain, x158_encrypted);
    encrypteds_vec.emplace_back(x158_encrypted);

    encryptor.encrypt(x1_plain, x159_encrypted);
    encrypteds_vec.emplace_back(x159_encrypted);

    encryptor.encrypt(x1_plain, x160_encrypted);
    encrypteds_vec.emplace_back(x160_encrypted);

    encryptor.encrypt(x1_plain, x161_encrypted);
    encrypteds_vec.emplace_back(x161_encrypted);

    encryptor.encrypt(x1_plain, x162_encrypted);
    encrypteds_vec.emplace_back(x162_encrypted);

    encryptor.encrypt(x1_plain, x163_encrypted);
    encrypteds_vec.emplace_back(x163_encrypted);

    encryptor.encrypt(x1_plain, x164_encrypted);
    encrypteds_vec.emplace_back(x164_encrypted);

    encryptor.encrypt(x1_plain, x165_encrypted);
    encrypteds_vec.emplace_back(x165_encrypted);

    encryptor.encrypt(x1_plain, x166_encrypted);
    encrypteds_vec.emplace_back(x166_encrypted);

    encryptor.encrypt(x1_plain, x167_encrypted);
    encrypteds_vec.emplace_back(x167_encrypted);

    encryptor.encrypt(x1_plain, x168_encrypted);
    encrypteds_vec.emplace_back(x168_encrypted);

    encryptor.encrypt(x1_plain, x169_encrypted);
    encrypteds_vec.emplace_back(x169_encrypted);

    encryptor.encrypt(x1_plain, x170_encrypted);
    encrypteds_vec.emplace_back(x170_encrypted);

    encryptor.encrypt(x1_plain, x171_encrypted);
    encrypteds_vec.emplace_back(x171_encrypted);

    encryptor.encrypt(x1_plain, x172_encrypted);
    encrypteds_vec.emplace_back(x172_encrypted);

    encryptor.encrypt(x1_plain, x173_encrypted);
    encrypteds_vec.emplace_back(x173_encrypted);

    encryptor.encrypt(x1_plain, x174_encrypted);
    encrypteds_vec.emplace_back(x174_encrypted);

    encryptor.encrypt(x1_plain, x175_encrypted);
    encrypteds_vec.emplace_back(x175_encrypted);

    encryptor.encrypt(x1_plain, x176_encrypted);
    encrypteds_vec.emplace_back(x176_encrypted);

    encryptor.encrypt(x1_plain, x177_encrypted);
    encrypteds_vec.emplace_back(x177_encrypted);

    encryptor.encrypt(x1_plain, x178_encrypted);
    encrypteds_vec.emplace_back(x178_encrypted);

    encryptor.encrypt(x1_plain, x179_encrypted);
    encrypteds_vec.emplace_back(x179_encrypted);

    encryptor.encrypt(x1_plain, x180_encrypted);
    encrypteds_vec.emplace_back(x180_encrypted);

    encryptor.encrypt(x1_plain, x181_encrypted);
    encrypteds_vec.emplace_back(x181_encrypted);

    encryptor.encrypt(x1_plain, x182_encrypted);
    encrypteds_vec.emplace_back(x182_encrypted);

    encryptor.encrypt(x1_plain, x183_encrypted);
    encrypteds_vec.emplace_back(x183_encrypted);

    encryptor.encrypt(x1_plain, x184_encrypted);
    encrypteds_vec.emplace_back(x184_encrypted);

    encryptor.encrypt(x1_plain, x185_encrypted);
    encrypteds_vec.emplace_back(x185_encrypted);

    encryptor.encrypt(x1_plain, x186_encrypted);
    encrypteds_vec.emplace_back(x186_encrypted);

    encryptor.encrypt(x1_plain, x187_encrypted);
    encrypteds_vec.emplace_back(x187_encrypted);

    encryptor.encrypt(x1_plain, x188_encrypted);
    encrypteds_vec.emplace_back(x188_encrypted);

    encryptor.encrypt(x1_plain, x189_encrypted);
    encrypteds_vec.emplace_back(x189_encrypted);

    encryptor.encrypt(x1_plain, x190_encrypted);
    encrypteds_vec.emplace_back(x190_encrypted);

    encryptor.encrypt(x1_plain, x191_encrypted);
    encrypteds_vec.emplace_back(x191_encrypted);

    encryptor.encrypt(x1_plain, x192_encrypted);
    encrypteds_vec.emplace_back(x192_encrypted);

    encryptor.encrypt(x1_plain, x193_encrypted);
    encrypteds_vec.emplace_back(x193_encrypted);

    encryptor.encrypt(x1_plain, x194_encrypted);
    encrypteds_vec.emplace_back(x194_encrypted);

    encryptor.encrypt(x1_plain, x195_encrypted);
    encrypteds_vec.emplace_back(x195_encrypted);

    encryptor.encrypt(x1_plain, x196_encrypted);
    encrypteds_vec.emplace_back(x196_encrypted);

    encryptor.encrypt(x1_plain, x197_encrypted);
    encrypteds_vec.emplace_back(x197_encrypted);

    encryptor.encrypt(x1_plain, x198_encrypted);
    encrypteds_vec.emplace_back(x198_encrypted);

    encryptor.encrypt(x1_plain, x199_encrypted);
    encrypteds_vec.emplace_back(x199_encrypted);

    encryptor.encrypt(x1_plain, x200_encrypted);
    encrypteds_vec.emplace_back(x200_encrypted);

    encryptor.encrypt(x1_plain, x201_encrypted);
    encrypteds_vec.emplace_back(x201_encrypted);

    encryptor.encrypt(x1_plain, x202_encrypted);
    encrypteds_vec.emplace_back(x202_encrypted);

    encryptor.encrypt(x1_plain, x203_encrypted);
    encrypteds_vec.emplace_back(x203_encrypted);

    encryptor.encrypt(x1_plain, x204_encrypted);
    encrypteds_vec.emplace_back(x204_encrypted);

    encryptor.encrypt(x1_plain, x205_encrypted);
    encrypteds_vec.emplace_back(x205_encrypted);

    encryptor.encrypt(x1_plain, x206_encrypted);
    encrypteds_vec.emplace_back(x206_encrypted);

    encryptor.encrypt(x1_plain, x207_encrypted);
    encrypteds_vec.emplace_back(x207_encrypted);

    encryptor.encrypt(x1_plain, x208_encrypted);
    encrypteds_vec.emplace_back(x208_encrypted);

    encryptor.encrypt(x1_plain, x209_encrypted);
    encrypteds_vec.emplace_back(x209_encrypted);

    encryptor.encrypt(x1_plain, x210_encrypted);
    encrypteds_vec.emplace_back(x210_encrypted);

    encryptor.encrypt(x1_plain, x211_encrypted);
    encrypteds_vec.emplace_back(x211_encrypted);

    encryptor.encrypt(x1_plain, x212_encrypted);
    encrypteds_vec.emplace_back(x212_encrypted);

    encryptor.encrypt(x1_plain, x213_encrypted);
    encrypteds_vec.emplace_back(x213_encrypted);

    encryptor.encrypt(x1_plain, x214_encrypted);
    encrypteds_vec.emplace_back(x214_encrypted);

    encryptor.encrypt(x1_plain, x215_encrypted);
    encrypteds_vec.emplace_back(x215_encrypted);

    encryptor.encrypt(x1_plain, x216_encrypted);
    encrypteds_vec.emplace_back(x216_encrypted);

    encryptor.encrypt(x1_plain, x217_encrypted);
    encrypteds_vec.emplace_back(x217_encrypted);

    encryptor.encrypt(x1_plain, x218_encrypted);
    encrypteds_vec.emplace_back(x218_encrypted);

    encryptor.encrypt(x1_plain, x219_encrypted);
    encrypteds_vec.emplace_back(x219_encrypted);

    encryptor.encrypt(x1_plain, x220_encrypted);
    encrypteds_vec.emplace_back(x220_encrypted);

    encryptor.encrypt(x1_plain, x221_encrypted);
    encrypteds_vec.emplace_back(x221_encrypted);

    encryptor.encrypt(x1_plain, x222_encrypted);
    encrypteds_vec.emplace_back(x222_encrypted);

    encryptor.encrypt(x1_plain, x223_encrypted);
    encrypteds_vec.emplace_back(x223_encrypted);

    encryptor.encrypt(x1_plain, x224_encrypted);
    encrypteds_vec.emplace_back(x224_encrypted);

    encryptor.encrypt(x1_plain, x225_encrypted);
    encrypteds_vec.emplace_back(x225_encrypted);

    encryptor.encrypt(x1_plain, x226_encrypted);
    encrypteds_vec.emplace_back(x226_encrypted);

    encryptor.encrypt(x1_plain, x227_encrypted);
    encrypteds_vec.emplace_back(x227_encrypted);

    encryptor.encrypt(x1_plain, x228_encrypted);
    encrypteds_vec.emplace_back(x228_encrypted);

    encryptor.encrypt(x1_plain, x229_encrypted);
    encrypteds_vec.emplace_back(x229_encrypted);

    encryptor.encrypt(x1_plain, x230_encrypted);
    encrypteds_vec.emplace_back(x230_encrypted);

    encryptor.encrypt(x1_plain, x231_encrypted);
    encrypteds_vec.emplace_back(x231_encrypted);

    encryptor.encrypt(x1_plain, x232_encrypted);
    encrypteds_vec.emplace_back(x232_encrypted);

    encryptor.encrypt(x1_plain, x233_encrypted);
    encrypteds_vec.emplace_back(x233_encrypted);

    encryptor.encrypt(x1_plain, x234_encrypted);
    encrypteds_vec.emplace_back(x234_encrypted);

    encryptor.encrypt(x1_plain, x235_encrypted);
    encrypteds_vec.emplace_back(x235_encrypted);

    encryptor.encrypt(x1_plain, x236_encrypted);
    encrypteds_vec.emplace_back(x236_encrypted);

    encryptor.encrypt(x1_plain, x237_encrypted);
    encrypteds_vec.emplace_back(x237_encrypted);

    encryptor.encrypt(x1_plain, x238_encrypted);
    encrypteds_vec.emplace_back(x238_encrypted);

    encryptor.encrypt(x1_plain, x239_encrypted);
    encrypteds_vec.emplace_back(x239_encrypted);

    encryptor.encrypt(x1_plain, x240_encrypted);
    encrypteds_vec.emplace_back(x240_encrypted);

    encryptor.encrypt(x1_plain, x241_encrypted);
    encrypteds_vec.emplace_back(x241_encrypted);

    encryptor.encrypt(x1_plain, x242_encrypted);
    encrypteds_vec.emplace_back(x242_encrypted);

    encryptor.encrypt(x1_plain, x243_encrypted);
    encrypteds_vec.emplace_back(x243_encrypted);

    encryptor.encrypt(x1_plain, x244_encrypted);
    encrypteds_vec.emplace_back(x244_encrypted);

    encryptor.encrypt(x1_plain, x245_encrypted);
    encrypteds_vec.emplace_back(x245_encrypted);

    encryptor.encrypt(x1_plain, x246_encrypted);
    encrypteds_vec.emplace_back(x246_encrypted);

    encryptor.encrypt(x1_plain, x247_encrypted);
    encrypteds_vec.emplace_back(x247_encrypted);

    encryptor.encrypt(x1_plain, x248_encrypted);
    encrypteds_vec.emplace_back(x248_encrypted);

    encryptor.encrypt(x1_plain, x249_encrypted);
    encrypteds_vec.emplace_back(x249_encrypted);

    encryptor.encrypt(x1_plain, x250_encrypted);
    encrypteds_vec.emplace_back(x250_encrypted);

    encryptor.encrypt(x1_plain, x251_encrypted);
    encrypteds_vec.emplace_back(x251_encrypted);

    encryptor.encrypt(x1_plain, x252_encrypted);
    encrypteds_vec.emplace_back(x252_encrypted);

    encryptor.encrypt(x1_plain, x253_encrypted);
    encrypteds_vec.emplace_back(x253_encrypted);

    encryptor.encrypt(x1_plain, x254_encrypted);
    encrypteds_vec.emplace_back(x254_encrypted);

    encryptor.encrypt(x1_plain, x255_encrypted);
    encrypteds_vec.emplace_back(x255_encrypted);
    
    encryptor.encrypt(x1_plain, x256_encrypted);
    encrypteds_vec.emplace_back(x256_encrypted);
    
    int n_threads = 128;
    #pragma omp parallel num_threads(n_threads)
    __itt_resume();
    #pragma omp parallel for
    for(int i=0;i<256;i+=2){
        // cout << "thread " <<endl; // to see how many threads are created
        evaluator.multiply_inplace(encrypteds_vec[i],encrypteds_vec[i+1]);
        evaluator.relinearize_inplace(encrypteds_vec[i], relin_keys);
        evaluator.rescale_to_next_inplace(encrypteds_vec[i]);
    }
    __itt_pause();
    
    //
    //First print the true result.
    //
    print_line(__LINE__);
    cout << "Decrypt and decode ((x1*x2))." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input1.size(); i++)
    {
        double x1 = input1[i];
        double x2 = input1[i];
        true_result.push_back((x1*x2));
    }
    print_vector(true_result, 5, 7);
    

    //
    //Decrypt, decode, and print the result.
    //

    //check all 128 values
    /*
    Plaintext plain_result;
    vector<double> result;
    
    for(int i=0;i<256;i+=2){
        decryptor.decrypt(encrypteds_vec[i], plain_result);
        encoder.decode(plain_result, result);
        cout << "    + Actual result(x" << to_string(i) <<"):" << endl;
        print_vector(result, 5, 7);
    }
    */
}
