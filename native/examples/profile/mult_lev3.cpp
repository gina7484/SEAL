#include "mult.h"
#include <ittnotify.h>


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
    Ciphertext x100_encrypted, x101_encrypted;

    
    encryptor.encrypt(x1_plain, x1_encrypted);
    encryptor.encrypt(x1_plain, x2_encrypted);
    encryptor.encrypt(x1_plain, x3_encrypted);
    encryptor.encrypt(x1_plain, x4_encrypted);
    encryptor.encrypt(x1_plain, x5_encrypted);
    encryptor.encrypt(x1_plain, x6_encrypted);
    encryptor.encrypt(x1_plain, x7_encrypted);
    encryptor.encrypt(x1_plain, x8_encrypted);
    encryptor.encrypt(x1_plain, x9_encrypted);
    encryptor.encrypt(x1_plain, x10_encrypted);
    encryptor.encrypt(x1_plain, x11_encrypted);
    encryptor.encrypt(x1_plain, x12_encrypted);
    encryptor.encrypt(x1_plain, x13_encrypted);
    encryptor.encrypt(x1_plain, x14_encrypted);
    encryptor.encrypt(x1_plain, x15_encrypted);
    encryptor.encrypt(x1_plain, x16_encrypted);
    encryptor.encrypt(x1_plain, x17_encrypted);
    encryptor.encrypt(x1_plain, x18_encrypted);
    encryptor.encrypt(x1_plain, x19_encrypted);
    encryptor.encrypt(x1_plain, x20_encrypted);
    encryptor.encrypt(x1_plain, x21_encrypted);
    encryptor.encrypt(x1_plain, x22_encrypted);
    encryptor.encrypt(x1_plain, x23_encrypted);
    encryptor.encrypt(x1_plain, x24_encrypted);
    encryptor.encrypt(x1_plain, x25_encrypted);
    encryptor.encrypt(x1_plain, x26_encrypted);
    encryptor.encrypt(x1_plain, x27_encrypted);
    encryptor.encrypt(x1_plain, x28_encrypted);
    encryptor.encrypt(x1_plain, x29_encrypted);
    encryptor.encrypt(x1_plain, x30_encrypted);
    encryptor.encrypt(x1_plain, x31_encrypted);
    encryptor.encrypt(x1_plain, x32_encrypted);
    encryptor.encrypt(x1_plain, x33_encrypted);
    encryptor.encrypt(x1_plain, x34_encrypted);
    encryptor.encrypt(x1_plain, x35_encrypted);
    encryptor.encrypt(x1_plain, x36_encrypted);
    encryptor.encrypt(x1_plain, x37_encrypted);
    encryptor.encrypt(x1_plain, x38_encrypted);
    encryptor.encrypt(x1_plain, x39_encrypted);
    encryptor.encrypt(x1_plain, x40_encrypted);
    encryptor.encrypt(x1_plain, x41_encrypted);
    encryptor.encrypt(x1_plain, x42_encrypted);
    encryptor.encrypt(x1_plain, x43_encrypted);
    encryptor.encrypt(x1_plain, x44_encrypted);
    encryptor.encrypt(x1_plain, x45_encrypted);
    encryptor.encrypt(x1_plain, x46_encrypted);
    encryptor.encrypt(x1_plain, x47_encrypted);
    encryptor.encrypt(x1_plain, x48_encrypted);
    encryptor.encrypt(x1_plain, x49_encrypted);
    encryptor.encrypt(x1_plain, x50_encrypted);
    encryptor.encrypt(x1_plain, x51_encrypted);
    encryptor.encrypt(x1_plain, x52_encrypted);
    encryptor.encrypt(x1_plain, x53_encrypted);
    encryptor.encrypt(x1_plain, x54_encrypted);
    encryptor.encrypt(x1_plain, x55_encrypted);
    encryptor.encrypt(x1_plain, x56_encrypted);
    encryptor.encrypt(x1_plain, x57_encrypted);
    encryptor.encrypt(x1_plain, x58_encrypted);
    encryptor.encrypt(x1_plain, x59_encrypted);
    encryptor.encrypt(x1_plain, x60_encrypted);
    encryptor.encrypt(x1_plain, x61_encrypted);
    encryptor.encrypt(x1_plain, x62_encrypted);
    encryptor.encrypt(x1_plain, x63_encrypted);
    encryptor.encrypt(x1_plain, x64_encrypted);
    encryptor.encrypt(x1_plain, x65_encrypted);
    encryptor.encrypt(x1_plain, x66_encrypted);
    encryptor.encrypt(x1_plain, x67_encrypted);
    encryptor.encrypt(x1_plain, x68_encrypted);
    encryptor.encrypt(x1_plain, x69_encrypted);
    encryptor.encrypt(x1_plain, x70_encrypted);
    encryptor.encrypt(x1_plain, x71_encrypted);
    encryptor.encrypt(x1_plain, x72_encrypted);
    encryptor.encrypt(x1_plain, x73_encrypted);
    encryptor.encrypt(x1_plain, x74_encrypted);
    encryptor.encrypt(x1_plain, x75_encrypted);
    encryptor.encrypt(x1_plain, x76_encrypted);
    encryptor.encrypt(x1_plain, x77_encrypted);
    encryptor.encrypt(x1_plain, x78_encrypted);
    encryptor.encrypt(x1_plain, x79_encrypted);
    encryptor.encrypt(x1_plain, x80_encrypted);
    encryptor.encrypt(x1_plain, x81_encrypted);
    encryptor.encrypt(x1_plain, x82_encrypted);
    encryptor.encrypt(x1_plain, x83_encrypted);
    encryptor.encrypt(x1_plain, x84_encrypted);
    encryptor.encrypt(x1_plain, x85_encrypted);
    encryptor.encrypt(x1_plain, x86_encrypted);
    encryptor.encrypt(x1_plain, x87_encrypted);
    encryptor.encrypt(x1_plain, x88_encrypted);
    encryptor.encrypt(x1_plain, x89_encrypted);
    encryptor.encrypt(x1_plain, x90_encrypted);
    encryptor.encrypt(x1_plain, x91_encrypted);
    encryptor.encrypt(x1_plain, x92_encrypted);
    encryptor.encrypt(x1_plain, x93_encrypted);
    encryptor.encrypt(x1_plain, x94_encrypted);
    encryptor.encrypt(x1_plain, x95_encrypted);
    encryptor.encrypt(x1_plain, x96_encrypted);
    encryptor.encrypt(x1_plain, x97_encrypted);
    encryptor.encrypt(x1_plain, x98_encrypted);
    encryptor.encrypt(x1_plain, x99_encrypted);
    encryptor.encrypt(x1_plain, x100_encrypted);
    encryptor.encrypt(x1_plain, x101_encrypted);
    

    /*
    [Multiplication]
    
    cout << "Compute, relinearize, and rescale x1 = x1 * x2" << endl;
    cout << "Compute, relinearize, and rescale x2 = x2 * x3" << endl;
    cout << "Compute, relinearize, and rescale x3 = x3 * x4" << endl;
    cout << "Compute, relinearize, and rescale x4 = x4 * x5" << endl;
    ...
    */
    __itt_resume();

    evaluator.multiply_inplace(x1_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x1_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x1_encrypted);
    
    evaluator.multiply_inplace(x2_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x2_encrypted);

    evaluator.multiply_inplace(x3_encrypted, x4_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x3_encrypted);

    evaluator.multiply_inplace(x4_encrypted, x5_encrypted);
    evaluator.relinearize_inplace(x4_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x4_encrypted);

    evaluator.multiply_inplace(x5_encrypted, x6_encrypted);
    evaluator.relinearize_inplace(x5_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x5_encrypted);

    evaluator.multiply_inplace(x6_encrypted, x7_encrypted);
    evaluator.relinearize_inplace(x6_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x6_encrypted);
    
    evaluator.multiply_inplace(x7_encrypted, x8_encrypted);
    evaluator.relinearize_inplace(x7_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x7_encrypted);

    evaluator.multiply_inplace(x8_encrypted, x9_encrypted);
    evaluator.relinearize_inplace(x8_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x8_encrypted);

    evaluator.multiply_inplace(x9_encrypted, x10_encrypted);
    evaluator.relinearize_inplace(x9_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x9_encrypted);

    evaluator.multiply_inplace(x10_encrypted, x11_encrypted);
    evaluator.relinearize_inplace(x10_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x10_encrypted);

    evaluator.multiply_inplace(x11_encrypted, x12_encrypted);
    evaluator.relinearize_inplace(x11_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x11_encrypted);

    evaluator.multiply_inplace(x12_encrypted, x13_encrypted);
    evaluator.relinearize_inplace(x12_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x12_encrypted);

    evaluator.multiply_inplace(x13_encrypted, x14_encrypted);
    evaluator.relinearize_inplace(x13_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x13_encrypted);

    evaluator.multiply_inplace(x14_encrypted, x15_encrypted);
    evaluator.relinearize_inplace(x14_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x14_encrypted);

    evaluator.multiply_inplace(x15_encrypted, x16_encrypted);
    evaluator.relinearize_inplace(x15_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x15_encrypted);

    evaluator.multiply_inplace(x16_encrypted, x17_encrypted);
    evaluator.relinearize_inplace(x16_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x16_encrypted);

    evaluator.multiply_inplace(x17_encrypted, x18_encrypted);
    evaluator.relinearize_inplace(x17_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x17_encrypted);

    evaluator.multiply_inplace(x18_encrypted, x19_encrypted);
    evaluator.relinearize_inplace(x18_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x18_encrypted);

    evaluator.multiply_inplace(x19_encrypted, x20_encrypted);
    evaluator.relinearize_inplace(x19_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x19_encrypted);

    evaluator.multiply_inplace(x20_encrypted, x21_encrypted);
    evaluator.relinearize_inplace(x20_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x20_encrypted);

    evaluator.multiply_inplace(x21_encrypted, x22_encrypted);
    evaluator.relinearize_inplace(x21_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x21_encrypted);

    evaluator.multiply_inplace(x22_encrypted, x23_encrypted);
    evaluator.relinearize_inplace(x22_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x22_encrypted);

    evaluator.multiply_inplace(x23_encrypted, x24_encrypted);
    evaluator.relinearize_inplace(x23_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x23_encrypted);

    evaluator.multiply_inplace(x24_encrypted, x25_encrypted);
    evaluator.relinearize_inplace(x24_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x24_encrypted);

    evaluator.multiply_inplace(x25_encrypted, x26_encrypted);
    evaluator.relinearize_inplace(x25_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x25_encrypted);

    evaluator.multiply_inplace(x26_encrypted, x27_encrypted);
    evaluator.relinearize_inplace(x26_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x26_encrypted);

    evaluator.multiply_inplace(x27_encrypted, x28_encrypted);
    evaluator.relinearize_inplace(x27_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x27_encrypted);

    evaluator.multiply_inplace(x28_encrypted, x29_encrypted);
    evaluator.relinearize_inplace(x28_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x28_encrypted);

    evaluator.multiply_inplace(x29_encrypted, x30_encrypted);
    evaluator.relinearize_inplace(x29_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x29_encrypted);

    evaluator.multiply_inplace(x30_encrypted, x31_encrypted);
    evaluator.relinearize_inplace(x30_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x30_encrypted);

    evaluator.multiply_inplace(x31_encrypted, x32_encrypted);
    evaluator.relinearize_inplace(x31_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x31_encrypted);

    evaluator.multiply_inplace(x32_encrypted, x33_encrypted);
    evaluator.relinearize_inplace(x32_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x32_encrypted);

    evaluator.multiply_inplace(x33_encrypted, x34_encrypted);
    evaluator.relinearize_inplace(x33_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x33_encrypted);

    evaluator.multiply_inplace(x34_encrypted, x35_encrypted);
    evaluator.relinearize_inplace(x34_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x34_encrypted);

    evaluator.multiply_inplace(x35_encrypted, x36_encrypted);
    evaluator.relinearize_inplace(x35_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x35_encrypted);

    evaluator.multiply_inplace(x36_encrypted, x37_encrypted);
    evaluator.relinearize_inplace(x36_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x36_encrypted);

    evaluator.multiply_inplace(x37_encrypted, x38_encrypted);
    evaluator.relinearize_inplace(x37_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x37_encrypted);

    evaluator.multiply_inplace(x38_encrypted, x39_encrypted);
    evaluator.relinearize_inplace(x38_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x38_encrypted);

    evaluator.multiply_inplace(x39_encrypted, x40_encrypted);
    evaluator.relinearize_inplace(x39_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x39_encrypted);

    evaluator.multiply_inplace(x40_encrypted, x41_encrypted);
    evaluator.relinearize_inplace(x40_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x40_encrypted);

    evaluator.multiply_inplace(x41_encrypted, x42_encrypted);
    evaluator.relinearize_inplace(x41_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x41_encrypted);

    evaluator.multiply_inplace(x42_encrypted, x43_encrypted);
    evaluator.relinearize_inplace(x42_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x42_encrypted);

    evaluator.multiply_inplace(x43_encrypted, x44_encrypted);
    evaluator.relinearize_inplace(x43_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x43_encrypted);

    evaluator.multiply_inplace(x44_encrypted, x45_encrypted);
    evaluator.relinearize_inplace(x44_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x44_encrypted);

    evaluator.multiply_inplace(x45_encrypted, x46_encrypted);
    evaluator.relinearize_inplace(x45_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x45_encrypted);

    evaluator.multiply_inplace(x46_encrypted, x47_encrypted);
    evaluator.relinearize_inplace(x46_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x46_encrypted);

    evaluator.multiply_inplace(x47_encrypted, x48_encrypted);
    evaluator.relinearize_inplace(x47_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x47_encrypted);

    evaluator.multiply_inplace(x48_encrypted, x49_encrypted);
    evaluator.relinearize_inplace(x48_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x48_encrypted);

    evaluator.multiply_inplace(x49_encrypted, x50_encrypted);
    evaluator.relinearize_inplace(x49_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x49_encrypted);

    evaluator.multiply_inplace(x50_encrypted, x51_encrypted);
    evaluator.relinearize_inplace(x50_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x50_encrypted);

    evaluator.multiply_inplace(x51_encrypted, x52_encrypted);
    evaluator.relinearize_inplace(x51_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x51_encrypted);

    evaluator.multiply_inplace(x52_encrypted, x53_encrypted);
    evaluator.relinearize_inplace(x52_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x52_encrypted);

    evaluator.multiply_inplace(x53_encrypted, x54_encrypted);
    evaluator.relinearize_inplace(x53_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x53_encrypted);

    evaluator.multiply_inplace(x54_encrypted, x55_encrypted);
    evaluator.relinearize_inplace(x54_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x54_encrypted);

    evaluator.multiply_inplace(x55_encrypted, x56_encrypted);
    evaluator.relinearize_inplace(x55_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x55_encrypted);

    evaluator.multiply_inplace(x56_encrypted, x57_encrypted);
    evaluator.relinearize_inplace(x56_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x56_encrypted);

    evaluator.multiply_inplace(x57_encrypted, x58_encrypted);
    evaluator.relinearize_inplace(x57_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x57_encrypted);

    evaluator.multiply_inplace(x58_encrypted, x59_encrypted);
    evaluator.relinearize_inplace(x58_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x58_encrypted);

    evaluator.multiply_inplace(x59_encrypted, x60_encrypted);
    evaluator.relinearize_inplace(x59_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x59_encrypted);

    evaluator.multiply_inplace(x60_encrypted, x61_encrypted);
    evaluator.relinearize_inplace(x60_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x60_encrypted);

    evaluator.multiply_inplace(x61_encrypted, x62_encrypted);
    evaluator.relinearize_inplace(x61_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x61_encrypted);

    evaluator.multiply_inplace(x62_encrypted, x63_encrypted);
    evaluator.relinearize_inplace(x62_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x62_encrypted);

    evaluator.multiply_inplace(x63_encrypted, x64_encrypted);
    evaluator.relinearize_inplace(x63_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x63_encrypted);

    evaluator.multiply_inplace(x64_encrypted, x65_encrypted);
    evaluator.relinearize_inplace(x64_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x64_encrypted);

    evaluator.multiply_inplace(x65_encrypted, x66_encrypted);
    evaluator.relinearize_inplace(x65_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x65_encrypted);

    evaluator.multiply_inplace(x66_encrypted, x67_encrypted);
    evaluator.relinearize_inplace(x66_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x66_encrypted);

    evaluator.multiply_inplace(x67_encrypted, x68_encrypted);
    evaluator.relinearize_inplace(x67_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x67_encrypted);

    evaluator.multiply_inplace(x68_encrypted, x69_encrypted);
    evaluator.relinearize_inplace(x68_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x68_encrypted);

    evaluator.multiply_inplace(x69_encrypted, x70_encrypted);
    evaluator.relinearize_inplace(x69_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x69_encrypted);

    evaluator.multiply_inplace(x70_encrypted, x71_encrypted);
    evaluator.relinearize_inplace(x70_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x70_encrypted);

    evaluator.multiply_inplace(x71_encrypted, x72_encrypted);
    evaluator.relinearize_inplace(x71_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x71_encrypted);

    evaluator.multiply_inplace(x72_encrypted, x73_encrypted);
    evaluator.relinearize_inplace(x72_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x72_encrypted);

    evaluator.multiply_inplace(x73_encrypted, x74_encrypted);
    evaluator.relinearize_inplace(x73_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x73_encrypted);

    evaluator.multiply_inplace(x74_encrypted, x75_encrypted);
    evaluator.relinearize_inplace(x74_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x74_encrypted);

    evaluator.multiply_inplace(x75_encrypted, x76_encrypted);
    evaluator.relinearize_inplace(x75_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x75_encrypted);

    evaluator.multiply_inplace(x76_encrypted, x77_encrypted);
    evaluator.relinearize_inplace(x76_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x76_encrypted);

    evaluator.multiply_inplace(x77_encrypted, x78_encrypted);
    evaluator.relinearize_inplace(x77_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x77_encrypted);

    evaluator.multiply_inplace(x78_encrypted, x79_encrypted);
    evaluator.relinearize_inplace(x78_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x78_encrypted);

    evaluator.multiply_inplace(x79_encrypted, x80_encrypted);
    evaluator.relinearize_inplace(x79_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x79_encrypted);

    evaluator.multiply_inplace(x80_encrypted, x81_encrypted);
    evaluator.relinearize_inplace(x80_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x80_encrypted);

    evaluator.multiply_inplace(x81_encrypted, x82_encrypted);
    evaluator.relinearize_inplace(x81_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x81_encrypted);

    evaluator.multiply_inplace(x82_encrypted, x83_encrypted);
    evaluator.relinearize_inplace(x82_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x82_encrypted);

    evaluator.multiply_inplace(x83_encrypted, x84_encrypted);
    evaluator.relinearize_inplace(x83_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x83_encrypted);

    evaluator.multiply_inplace(x84_encrypted, x85_encrypted);
    evaluator.relinearize_inplace(x84_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x84_encrypted);

    evaluator.multiply_inplace(x85_encrypted, x86_encrypted);
    evaluator.relinearize_inplace(x85_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x85_encrypted);

    evaluator.multiply_inplace(x86_encrypted, x87_encrypted);
    evaluator.relinearize_inplace(x86_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x86_encrypted);

    evaluator.multiply_inplace(x87_encrypted, x88_encrypted);
    evaluator.relinearize_inplace(x87_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x87_encrypted);

    evaluator.multiply_inplace(x88_encrypted, x89_encrypted);
    evaluator.relinearize_inplace(x88_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x88_encrypted);

    evaluator.multiply_inplace(x89_encrypted, x90_encrypted);
    evaluator.relinearize_inplace(x89_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x89_encrypted);

    evaluator.multiply_inplace(x90_encrypted, x91_encrypted);
    evaluator.relinearize_inplace(x90_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x90_encrypted);

    evaluator.multiply_inplace(x91_encrypted, x92_encrypted);
    evaluator.relinearize_inplace(x91_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x91_encrypted);

    evaluator.multiply_inplace(x92_encrypted, x93_encrypted);
    evaluator.relinearize_inplace(x92_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x92_encrypted);

    evaluator.multiply_inplace(x93_encrypted, x94_encrypted);
    evaluator.relinearize_inplace(x93_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x93_encrypted);

    evaluator.multiply_inplace(x94_encrypted, x95_encrypted);
    evaluator.relinearize_inplace(x94_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x94_encrypted);

    evaluator.multiply_inplace(x95_encrypted, x96_encrypted);
    evaluator.relinearize_inplace(x95_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x95_encrypted);

    evaluator.multiply_inplace(x96_encrypted, x97_encrypted);
    evaluator.relinearize_inplace(x96_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x96_encrypted);

    evaluator.multiply_inplace(x97_encrypted, x98_encrypted);
    evaluator.relinearize_inplace(x97_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x97_encrypted);

    evaluator.multiply_inplace(x98_encrypted, x99_encrypted);
    evaluator.relinearize_inplace(x98_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x98_encrypted);

    evaluator.multiply_inplace(x99_encrypted, x100_encrypted);
    evaluator.relinearize_inplace(x99_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x99_encrypted);

    evaluator.multiply_inplace(x100_encrypted, x101_encrypted);
    evaluator.relinearize_inplace(x100_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x100_encrypted);
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
    Plaintext plain_result;
    decryptor.decrypt(x1_encrypted, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Actual result(x1):" << endl;
    print_vector(result, 5, 7);

    decryptor.decrypt(x2_encrypted, plain_result);
    encoder.decode(plain_result, result);
    cout << "    + Actual result(x2):" << endl;
    print_vector(result, 5, 7);

    decryptor.decrypt(x4_encrypted, plain_result);
    encoder.decode(plain_result, result);
    cout << "    + Actual result(x4):" << endl;
    print_vector(result, 5, 7);

    decryptor.decrypt(x14_encrypted, plain_result);
    encoder.decode(plain_result, result);
    cout << "    + Actual result(x14):" << endl;
    print_vector(result, 5, 7);

    decryptor.decrypt(x99_encrypted, plain_result);
    encoder.decode(plain_result, result);
    cout << "    + Actual result(x99):" << endl;
    print_vector(result, 5, 7);

}
