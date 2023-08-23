#include "openpgp_layer.h"
#include "test/openpgp_layer_test.h"
#include "test/openpgp_layer_test_vectors.h"
#include "utils/utils.h"
#include "external_deps/print.h"

int main(int argc, char* argv[]) {
	int ret;

	(void)argc;
	(void)argv;

	ret = openpgp_libecc_test_ecdh(&KOpenPGPLayerDHTestValue_Nist384_1);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDH for KOpenPGPLayerTestVector_Nist384_1 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDH for KOpenPGPLayerTestVector_Nist384_1 is OK\n");
	ret = openpgp_libecc_test_ecdh(&KOpenPGPLayerDHTestValue_Nist521_1);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDH for KOpenPGPLayerTestVector_Nist521_1 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDH for KOpenPGPLayerTestVector_Nist521_1 is OK\n");
	ret = openpgp_libecc_test_ecdh(&KOpenPGPLayerDHTestValue_Curve25519Legacy_1);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_1 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_1 is OK\n");
	ret = openpgp_libecc_test_ecdh(&KOpenPGPLayerDHTestValue_Curve25519Legacy_2);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_2 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDH for KOpenPGPLayerTestVector_Curve25519Legacy_2 is OK\n");
	ret = openpgp_libecc_test_ecdsa_verify(&KOpenPGPLayerParams_ECDSA_1);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDSA for KOpenPGPLayerParams_ECDSA_1 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDSA for KOpenPGPLayerParams_ECDSA_1 is OK\n");
	ret = openpgp_libecc_test_ecdsa_verify(&KOpenPGPLayerParams_ECDSA_2);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDSA for KOpenPGPLayerParams_ECDSA_2 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDSA for KOpenPGPLayerParams_ECDSA_2 is OK\n");
	ret = openpgp_libecc_test_ecdsa_sign_and_verify_cycle(&KOpenPGPLayerParams_ECDSA_3);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDSA for KOpenPGPLayerParams_ECDSA_3 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDSA for KOpenPGPLayerParams_ECDSA_3 is OK\n");
	ret = openpgp_libecc_test_ecdsa_sign_and_verify_cycle(&KOpenPGPLayerParams_ECDSA_4);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDSA for KOpenPGPLayerParams_ECDSA_4 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDSA for KOpenPGPLayerParams_ECDSA_4 is OK\n");
	ret = openpgp_libecc_test_ecdsa_sign_and_verify_cycle(&KOpenPGPLayerParams_ECDSA_5);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] ECDSA for KOpenPGPLayerParams_ECDSA_5 is KO\n");
		goto err;
	}
	ext_printf("[+] ECDSA for KOpenPGPLayerParams_ECDSA_5 is OK\n");
	ret = openpgp_libecc_test_ecdsa_sign_and_verify_cycle(&KOpenPGPLayerParams_EdDSA_1);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] EdDSA for KOpenPGPLayerParams_EdDSA_1 is KO\n");
		goto err;
	}
	ext_printf("[+] EdDSA for KOpenPGPLayerParams_EdDSA_1 is OK\n");
	ret = openpgp_libecc_test_ecdsa_sign_and_verify_cycle(&KOpenPGPLayerParams_EdDSA_2);
	if(ret != KOpenPGPEllipticTest_OK){
		ext_printf("[-] EdDSA for KOpenPGPLayerParams_EdDSA_2 is KO\n");
		goto err;
	}
	ext_printf("[+] EdDSA for KOpenPGPLayerParams_EdDSA_2 is OK\n");


	return 0;

err:
	return -1;
}
