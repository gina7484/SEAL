#include "profile_mult.h"
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
    
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

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
    cout << "Generate input1, input2, input3" << endl;
    vector<double> input1;
    input1.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input1.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "    Input vector1: " << endl;
    print_vector(input1, 5, 7);

    vector<double> input2;
    input2.reserve(slot_count);
    curr_point = 0;
    step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input2.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "    Input vector2: " << endl;
    print_vector(input2, 5, 7);

    vector<double> input3;
    input3.reserve(slot_count);
    curr_point = 0;
    step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input3.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "    Input vector3: " << endl;
    print_vector(input3, 5, 7);

    cout << "Encode input vectors." << endl;
    Plaintext x1_plain, x2_plain, x3_plain;
    encoder.encode(input1, scale, x1_plain);
    encoder.encode(input2, scale, x2_plain);
    encoder.encode(input3, scale, x3_plain);

    Ciphertext x1_encrypted, x2_encrypted, x3_encrypted;
    encryptor.encrypt(x1_plain, x1_encrypted);
    encryptor.encrypt(x2_plain, x2_encrypted);
    encryptor.encrypt(x3_plain, x3_encrypted);

    /*
    [Multiplication]
    */
    cout << "Compute, relinearize, and rescale x1=x1*x2" << endl;
    cout << "Compute, relinearize, and rescale x2=x2*x3" << endl;
    cout << "Compute, relinearize, and rescale x1=x1*x2" << endl;
    __itt_resume();
    evaluator.multiply_inplace(x1_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x1_encrypted, relin_keys);
    // cout << "    + Scale before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    // cout << "    + Scale after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    evaluator.multiply_inplace(x2_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x2_encrypted);

    evaluator.multiply_inplace(x1_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x1_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x1_encrypted);

    __itt_pause();
    
    /*
    First print the true result.
    */
    print_line(__LINE__);
    cout << "Decrypt and decode (x1*x2)*(x2*x3)." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input1.size(); i++)
    {
        double x1 = input1[i];
        double x2 = input2[i];
        double x3 = input3[i];
        true_result.push_back((x1*x2)*(x2*x3));
    }
    print_vector(true_result, 5, 7);
    

    /*
    Decrypt, decode, and print the result.
    */
    Plaintext plain_result;
    decryptor.decrypt(x1_encrypted, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Actual result:" << endl;
    print_vector(result, 5, 7);

}
