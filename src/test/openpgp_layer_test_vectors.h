#ifndef OPENPGP_LAYER_TEST_VECTORS_H
#define OPENPGP_LAYER_TEST_VECTORS_H

#include "../openpgp_layer_types.h"

const ecdh_params KOpenPGPLayerDHTestParams_Nist384_1 = {
	"\x04\x73\xff\x6e\xfb\x28\x11\x48\xe1\x75\x76\x82\x53\xfe\x53\xc5\x47\x61\x68\xf6\x93\xd5\x89\x75\x01\x1c\x0b\x88\x4c\x97\xdd\xd4\x3c\xd9\xa9\x1c\xf3\x3f\xff\xe4\x2e\x99\xff\x1f\xa7\x4d\x8f\x71\x16\x09\x95\xc3\x3e\xdd\x3f\x43\x5f\xb4\x2e\x85\x5e\xc2\x6c\x15\xbe\x41\xe1\xa8\xab\x5a\x38\x2b\xcd\x71\x96\xcb\x18\x9a\x3b\x45\xb2\x12\x09\x86\x2a\x97\x29\x23\x0b\x25\xc9\x4d\x19\xdb\x6a\x1e\x3c",
	97,
	"\x03\xe5\x0e\x19\xfe\xb8\x99\xd3\x82\x4a\xf4\x96\xbc\x7a\xa3\xe8\xd0\xec\x96\xec\x34\x24\x48\xf0\xd0\xc3\x57\xd7\x1c\x05\x17\xed\xaa\x57\x8b\x9b\x69\x3b\x81\x61\x6e\xf6\x66\x45\x16\x16\x43\x75",
	48,
	"\x04\xb5\x5c\x51\x19\x9b\x98\x3e\x94\xc9\xe6\x56\x66\x48\x07\xa6\xf0\x68\xe8\xa6\xbb\xa3\x22\x47\x93\x31\x71\x11\xf0\xf9\x79\xb4\x2b\x22\xc3\xd1\x43\xae\x5a\xc7\x77\x1d\x80\x9e\x9c\x42\x0d\x71\x86\x9b\x64\x93\x1d\x70\x3a\xc5\x25\x3b\xa6\x58\x53\xf9\xa0\x26\x27\x96\xb7\xf8\xc0\x81\x3f\x11\x7d\x2e\x65\x81\x44\xdc\xa1\xe9\xff\x19\x2b\x4d\xb1\x16\x8c\xe9\x6a\xc7\x5e\x0e\x9d\x5a\x29\x34\xad",
	97,
	SECP384R1,
};

const ecdh_result KOpenPGPLayerDHTestResult_Nist384_1 = {
	"\x36\x4f\xc6\xfe\x9f\x2d\x7a\x4f\xf0\x75\x10\xa7\x5d\x99\x74\x51\xa5\x1d\xc9\x1f\xc0\x9f\x09\x9f\x46\x8b\x48\x21\xb5\x25\x7e\xff\xb4\x4f\x76\x82\x5e\xea\x17\x70\x19\x1e\xb6\x20\x6b\x37\x89\x06",
	48,
	"\x04\xb5\x5c\x51\x19\x9b\x98\x3e\x94\xc9\xe6\x56\x66\x48\x07\xa6\xf0\x68\xe8\xa6\xbb\xa3\x22\x47\x93\x31\x71\x11\xf0\xf9\x79\xb4\x2b\x22\xc3\xd1\x43\xae\x5a\xc7\x77\x1d\x80\x9e\x9c\x42\x0d\x71\x86\x9b\x64\x93\x1d\x70\x3a\xc5\x25\x3b\xa6\x58\x53\xf9\xa0\x26\x27\x96\xb7\xf8\xc0\x81\x3f\x11\x7d\x2e\x65\x81\x44\xdc\xa1\xe9\xff\x19\x2b\x4d\xb1\x16\x8c\xe9\x6a\xc7\x5e\x0e\x9d\x5a\x29\x34\xad",
	97,
	"\xb7\xe0\x61\xbf\x3c\xd2\xe4\x3e\xc9\xa0\xf1\x37\xa2\x37\xda\xaa\x31\x7e\x21\xc6\x0e\x8e\x6c\xbe\xe0\x8f\xdd\xc2\xae\x74\xb5\xac\xb2\xa3\x93\xca\xc3\x87\xd2\x99\x1f\xd3\xac\xae\xbf\x54\x0d\x09",
	48
};

const ecdh_test_value KOpenPGPLayerDHTestValue_Nist384_1 = {
	&KOpenPGPLayerDHTestParams_Nist384_1,
	&KOpenPGPLayerDHTestResult_Nist384_1
};

const ecdh_params KOpenPGPLayerDHTestParams_Nist521_1 = {
	"\x04\x01\xe2\x20\x07\x51\xce\xcc\xae\x22\x27\x5d\x83\x5e\x76\x8f\xa7\x92\x30\xe8\x6a\x5a\x71\x8c\x80\x96\xfb\xcf\x63\x1b\xb6\x4b\x87\x75\xa4\x37\xaa\x6d\x43\x39\x02\xa8\x9b\x72\x5b\x99\xcb\x0d\xab\x27\xee\xe1\x69\xeb\xd2\x91\x60\x0a\x32\xf5\x0f\xec\xb5\xd5\xb6\x0f\x34\x00\x97\xf8\xb9\x34\x07\xde\x9c\x50\x24\xad\x3d\x46\x30\xa9\x9d\x0a\x34\xe5\x2f\xfd\xb2\xe5\xa3\x8a\x55\xc5\x2e\x12\x3f\x69\xbe\x6d\x8c\xc7\x94\xe2\x28\xa0\x7f\x08\x92\xa9\x1f\xfd\xb8\xb6\x59\x1e\xfb\x19\x38\x2b\xc9\xb3\xa5\x19\x87\x33\x2f\xa0\x4b\xcf\x8e\xd4\x98",
	133,
	"\x01\x1b\xdf\x36\xd5\xb9\x72\x80\x91\x4d\x3e\x1b\x12\x8d\xf1\xb1\xc0\x5a\x5a\x3d\xe5\xa9\x58\x19\x9a\x96\x12\x64\xf7\xe5\x76\x17\x0a\x46\xe7\x1a\x49\xc7\x2f\x96\x4c\x06\x83\x86\x41\xf5\xf5\xb6\xff\x6b\x13\xaa\xb2\x0e\xee\x75\x76\x25\x81\xb3\xb6\x4a\x34\x06\x98\x04",
	66,
	"\x04\x01\xd0\x84\x6b\x6b\xeb\x3f\x47\x2b\x07\xcf\xb5\x45\xb0\xbb\xfd\x33\xd0\xcb\xcd\xef\x2f\x61\xfe\xab\x88\x0b\x14\xaf\xc8\xa0\x70\x37\xbf\x3c\x06\x13\x6e\x6b\xa9\x2e\x91\x0c\x24\xac\x85\x31\x9c\xf2\x18\x8d\x30\x6d\xb3\x87\xf8\x19\xe0\x15\x3d\x04\x03\xb1\x3c\xc6\x15\x01\x49\x55\x60\x74\x52\x41\xc2\xad\x7b\x94\x37\xf8\xff\x64\x7f\xb5\x56\x3c\xf8\xca\x60\x8b\xb0\xc7\x72\xb0\xe9\xb4\x2f\x9a\x06\xc6\xe1\xfb\x7e\x17\x34\x32\x60\x5b\x7e\xe1\xff\x13\x56\x21\x8c\xfa\x8a\xa1\xe8\x61\x42\x62\x65\x2b\x72\xe5\x76\xe6\xf4\x52\x65\x43\x1a",
	133,
	SECP521R1
};

const ecdh_result KOpenPGPLayerDHTestResult_Nist521_1 = {
	"\x00\x88\x81\x07\x57\x31\x91\x4c\xef\x07\x40\xbb\x42\xcc\x1f\xca\x0f\x77\xd7\xe2\xb9\x2a\x9d\x04\xac\xcc\xe1\x80\x9c\x9e\x45\x49\x70\xa1\xa4\xef\xa0\xd8\x0c\x42\x1f\xf2\x48\xb7\xf5\x85\xd8\x72\x43\xcf\xe1\x11\x87\x3c\xca\xd7\xe1\x41\xbb\xce\x88\x41\x30\xd8\x56\x37",
	66,
	"\x04\x01\xd0\x84\x6b\x6b\xeb\x3f\x47\x2b\x07\xcf\xb5\x45\xb0\xbb\xfd\x33\xd0\xcb\xcd\xef\x2f\x61\xfe\xab\x88\x0b\x14\xaf\xc8\xa0\x70\x37\xbf\x3c\x06\x13\x6e\x6b\xa9\x2e\x91\x0c\x24\xac\x85\x31\x9c\xf2\x18\x8d\x30\x6d\xb3\x87\xf8\x19\xe0\x15\x3d\x04\x03\xb1\x3c\xc6\x15\x01\x49\x55\x60\x74\x52\x41\xc2\xad\x7b\x94\x37\xf8\xff\x64\x7f\xb5\x56\x3c\xf8\xca\x60\x8b\xb0\xc7\x72\xb0\xe9\xb4\x2f\x9a\x06\xc6\xe1\xfb\x7e\x17\x34\x32\x60\x5b\x7e\xe1\xff\x13\x56\x21\x8c\xfa\x8a\xa1\xe8\x61\x42\x62\x65\x2b\x72\xe5\x76\xe6\xf4\x52\x65\x43\x1a",
	133,
	"\x01\x31\x88\xe0\x40\x6e\x05\xf5\x66\x6f\xdd\x84\xa9\x16\xed\xe6\x10\x11\xe0\x2e\x41\x42\xd3\xcd\x5f\x82\x90\xb0\xb7\xa9\x0c\xc3\xe3\xb2\xd9\x6d\x39\x16\x00\xe1\x0f\x52\x3d\xe9\x7a\x61\xc9\x1e\xc9\x01\x6d\x12\x77\x47\x7a\x2b\x5d\x89\x2e\x77\x4b\x11\x42\xd7\x4c\x14",
	66
};

const ecdh_test_value KOpenPGPLayerDHTestValue_Nist521_1 = {
	&KOpenPGPLayerDHTestParams_Nist521_1,
	&KOpenPGPLayerDHTestResult_Nist521_1
};

const ecdh_params KOpenPGPLayerDHTestParams_Curve25519Legacy_1 = {
	"\x40\xeb\xe2\x84\x1c\x37\x66\x53\xd2\x32\x0e\xae\xeb\x7e\xd7\xe9\xcf\x86\x67\x69\x44\x55\x6b\x92\x1b\xec\x47\x1f\x21\x2f\x7d\xc3\x75",
	33,
	"\x56\x08\xea\xff\xb3\x2e\x62\x9e\x62\x08\x97\x82\xdc\x91\x78\x1d\xc9\xb8\x51\x1e\x6d\xd8\xe8\x79\x01\x0a\x0e\xf4\xf1\x63\x91\x18",
	32,
	"\x40\x2b\xb1\x88\x56\x89\x3c\x92\x73\xb5\x83\xfb\x92\x18\x7f\xa5\xe7\x47\x71\x40\x04\x50\x6e\x97\xeb\x9c\x56\x07\xa1\x28\x62\xbe\x50",
	33,
	WEI25519
};

const ecdh_result KOpenPGPLayerDHTestResult_Curve25519Legacy_1 = {
	"\xe0\x8b\x47\xa0\x11\xb5\x1f\x18\x48\xf1\x99\x44\xb6\xd5\x4c\xd1\x5c\x2c\xba\x29\xf9\x80\xee\x84\x18\x6f\xfd\xa2\xb0\x2a\xaf\x40",
	32,
	"\x40\x2b\xb1\x88\x56\x89\x3c\x92\x73\xb5\x83\xfb\x92\x18\x7f\xa5\xe7\x47\x71\x40\x04\x50\x6e\x97\xeb\x9c\x56\x07\xa1\x28\x62\xbe\x50",
	33,
	"\x9c\xff\x25\x56\xe2\x3c\x97\xa3\x5b\xc3\xe1\xb9\xd1\x39\x44\x98\x55\x5f\xf8\xd5\xcb\x72\x09\x35\xcd\x01\x52\x67\x08\x96\x89\x1b",
	32
};

const ecdh_test_value KOpenPGPLayerDHTestValue_Curve25519Legacy_1 = {
	&KOpenPGPLayerDHTestParams_Curve25519Legacy_1,
	&KOpenPGPLayerDHTestResult_Curve25519Legacy_1
};

const ecdh_params KOpenPGPLayerDHTestParams_Curve25519Legacy_2 = {
	"\x40\xeb\xe2\x84\x1c\x37\x66\x53\xd2\x32\x0e\xae\xeb\x7e\xd7\xe9\xcf\x86\x67\x69\x44\x55\x6b\x92\x1b\xec\x47\x1f\x21\x2f\x7d\xc3\x75",
	33,
	"\x56\x08\xea\xff\xb3\x2e\x62\x9e\x62\x08\x97\x82\xdc\x91\x78\x1d\xc9\xb8\x51\x1e\x6d\xd8\xe8\x79\x01\x0a\x0e\xf4\xf1\x63\x91\x18",
	32,
	"\x40\x36\x76\x98\x1d\x3b\x02\xaa\x4c\x8c\xeb\x84\x4f\x90\x61\x73\x30\x1c\x8e\xfc\x99\x0c\x3f\x62\xfb\x64\xa5\x41\x38\x48\xcf\x5b\x2f",
	33,
	WEI25519
};

const ecdh_result KOpenPGPLayerDHTestResult_Curve25519Legacy_2 = {
	"\x58\xdc\x9b\x53\x5c\xd9\x26\x8f\x53\x8a\x11\xbc\x1f\x6f\xee\xac\x1e\x17\x5a\x98\x81\x36\x0a\xef\x4c\xf2\xb7\x3e\x07\xe3\x76\x47",
	32,
	"\x40\x36\x76\x98\x1d\x3b\x02\xaa\x4c\x8c\xeb\x84\x4f\x90\x61\x73\x30\x1c\x8e\xfc\x99\x0c\x3f\x62\xfb\x64\xa5\x41\x38\x48\xcf\x5b\x2f",
	33,
	"\x0b\x1e\x94\x4d\x8c\x75\xae\xad\x38\x72\x52\x81\x4b\xaa\x46\xdd\x36\x1b\x4b\xbb\x3e\x98\xe3\xe1\x2d\xc7\xd0\xfa\x98\xbb\xcb\x3e",
	32
};

const ecdh_test_value KOpenPGPLayerDHTestValue_Curve25519Legacy_2 = {
	&KOpenPGPLayerDHTestParams_Curve25519Legacy_2,
	&KOpenPGPLayerDHTestResult_Curve25519Legacy_2
};

const ecdsa_params KOpenPGPLayerParams_ECDSA_1 = {
	  "\x04\x6d\xdb\xfa\xf8\x66\x50\x66\x59\xfb\x19\xbf\xda\x50\x31\x81\xe7\x96\x55\x59\xe9\xa9\x3d\xa4\x00\x12\xd4\x85\x75\x17\x59\xd2\xa1\xdb\xf2\x93\x77\xc8\xf5\xca\xcd\x26\x40\xdd\xca\xde\x5a\x83\x47\x82\x4d\x56\xd0\x8f\x04\x8f\x74\xb1\x92\xa6\x97\x02\xa7\x77\xbe\xec\x62\x2e\xf3\x40\xbc\x3d\x7c\xb4\x10\x28\x38\x75\x49\xf9\x2d\x5c\x8f\xa9\x48\x0f\x7d\x92\x47\x04\xc9\xd0\x29\x57\xa9\xc2\x7a",
	  97,
	  "",
	  0,
	  "\xe0\xa1\x24\x86\x0d\xb4\x62\x3a\xf0\x21\xd0\x1e\x4e\xef\x6a\x8c\x8c\x3a\x0d\xee\x0a\x5e\x39\xdd\x3d\x4c\x6d\x37\x9f\xeb\x86\x12\xb3\x46\x9b\x11\x07\x31\xc3\xf2\xbb\xcd\x46\xa1\x2f\x8f\x2d\xc4",
	  48,
	  "",
	  0,
	  "\x48\xef\x89\x40\x4d\xe2\xcf\xe7\x3e\xb9\x51\x73\x14\x97\x85\x94\xdd\x68\x89\x7f\xb9\xb6\x93\xd7\xf2\x8e\x67\xcc\x5d\x93\xb9\xe1\xaf\xef\x6e\x29\x68\xcb\xa9\x68\x8d\x58\x74\xd9\x74\x56\xaf\x11",
	  48,
	  "\x2d\xc1\xae\x60\x54\xed\x6c\x14\x82\xd2\xe5\x08\x34\x3e\xb9\xa8\x48\x48\x5b\xe2\x44\x36\xfb\x0a\x09\xe1\x64\x74\xe5\xa1\xaa\x3b\xaf\x19\xa3\x7c\x27\xbe\x18\x81\x56\x27\xac\xee\x16\x4c\x52\x8c",
	  48,
	  BRAINPOOLP384R1,
	  SHA384
};

const ecdsa_params KOpenPGPLayerParams_ECDSA_2 = {
	  "\x04\x02\xe5\xe8\x95\xc2\xa9\xf3\x5b\xe6\x47\x8f\xba\xde\xab\xbe\x16\xaa\x3d\x0c\xa0\xc4\xca\x34\x9a\xe7\x69\x6a\xfb\x2b\xd1\x00\xd7\xb1\x71\xe9\xd5\x09\x19\xb6\x2b\xf9\x45\x4f\xd7\x52\xa1\x68\x69\x3f\x90\x73\x6d\x19\x88\x91\x01\x4b\xb5\x37\xd1\x49\xaf\x3b\x05\xbd\x24\xcf\x4b\x46\x2e\x55\xeb\x7d\x1b\xea\x52\xa3\xaf\x4c\x19\xf2\x7a\xe3\x52\x78\xd4\xa8\x29\xe5\x0e\x6f\x37\xad\x21\x2d\x20",
	  97,
	  "",
	  0,
	  "\x0b\x0f\xab\xa6\x04\x70\x1a\xe3\x8c\x8d\xfb\x17\x77\xd3\x1a\x44\xc8\x3d\xa0\xac\x84\xba\x7d\x90\x85\x42\xa5\x48\xcd\x21\x9b\x64\x5e\x47\xbe\x23\xb2\x16\x62\x86\x3d\xbf\x7e\x93\xd2\xa7\x47\xb4",
	  48,
	  "",
	  0,
	  "\x81\xe1\xc1\x68\x69\x45\xf3\x37\x38\x7e\x2a\x12\x33\xd5\x23\xb3\x51\x28\x4c\xd6\xa8\x0d\x18\xdf\x9e\x84\x28\x03\x1d\x10\x37\x4a\xb9\xae\x09\xf9\x11\x7c\xb0\xb3\x58\x41\xe2\x6c\x2d\x7a\x89\x83",
	  48,
	  "\x67\x35\xe5\x15\xfa\xa7\x3e\x96\x76\x10\x4f\x4c\xab\x3a\xa2\x68\xe8\xd7\x72\xb3\x52\x42\x6b\x3f\xde\xcd\x8d\x40\x60\x4a\xc4\x80\xf5\xd3\xe5\xa2\xef\xd5\x77\x99\xd3\x23\x7d\xdc\xf4\xcc\x04\x0d",
	  48,
	  BRAINPOOLP384R1,
	  SHA384
};

const ecdsa_params KOpenPGPLayerParams_ECDSA_3 = {
	  "\x04\x02\xe5\xe8\x95\xc2\xa9\xf3\x5b\xe6\x47\x8f\xba\xde\xab\xbe\x16\xaa\x3d\x0c\xa0\xc4\xca\x34\x9a\xe7\x69\x6a\xfb\x2b\xd1\x00\xd7\xb1\x71\xe9\xd5\x09\x19\xb6\x2b\xf9\x45\x4f\xd7\x52\xa1\x68\x69\x3f\x90\x73\x6d\x19\x88\x91\x01\x4b\xb5\x37\xd1\x49\xaf\x3b\x05\xbd\x24\xcf\x4b\x46\x2e\x55\xeb\x7d\x1b\xea\x52\xa3\xaf\x4c\x19\xf2\x7a\xe3\x52\x78\xd4\xa8\x29\xe5\x0e\x6f\x37\xad\x21\x2d\x20",
	  97,
	  "\x3a\xba\x46\x0c\xd1\x55\x87\x8f\x0a\x9e\x2b\xcc\xb9\x91\x56\x49\x0a\x9b\x0e\x29\xae\x7e\x69\x79\x48\xfe\x89\x76\x3a\x7d\xb8\xfb\xdf\x7d\x41\xbe\xbe\xc0\x64\x91\x5a\x30\xef\xf2\xe8\xbd\xd6\xfa",
	  48,
	  "\xe6\x62\x3d\x14\xd7\xe3\xbd\x3c\x90\xc5\x60\x85\xa3\x0e\x6f\xcc\xf5\x17\xdb\x5a\x9b\x6a\x03\x40\x62\xd2\xca\x65\xf6\x69\x30\x55\x35\x8d\xdc\xa5\x27\xfe\x35\x94\x1d\xf2\x19\x9a\xa9\x34\x5e\x8b\x72\x41\xb6\x0b\xf6\xb2\x9b\xf8\x3b\x20\xd8\x34\x84\x82\x17\xcb",
	  64,
	  "\x25\x4d\xc0\x42\x61\xe0\x56\xf6\xdc\x1e\x64\x93\x23\x1f\x94\x36\x16\xf1\x7b\x61\x5b\x06\x51\x87\x5b\x20\x78\xed\xae\xdf\xbd\x82\x71\xdc\x1d\xf2\xfa\xc2\xb5\x5f\xdd\x64\xdf\x8e\x22\x5c\x37\xc2",
	  48,
	  "\x24\x87\x43\x68\x7d\xbb\x4b\x56\xa9\x53\xb3\x54\x46\x67\x6b\xa0\x2b\xb6\xa8\x34\xc8\xc3\x0f\x6f\xde\x94\x1d\x71\x00\xca\xdd\xd4\xdc\x98\x46\xac\xac\xba\xc5\x9d\x8d\xe7\x06\xd1\x40\x11\x7d\x8f",
	  48,
	  "\x1f\x75\x11\x99\x08\x9a\x5e\x16\xfc\x00\xe4\x22\xfc\x76\x32\x17\x8d\x0f\xac\x31\x65\x30\xc9\xf1\x26\x70\x05\x88\xbb\x52\x59\x1c\x46\x3b\xfe\x30\xd5\x9a\x6a\x56\x22\xf6\xf8\x21\xcf\x2a\xea\xa1",
	  48,
	  BRAINPOOLP384R1,
	  SHA384
};

const ecdsa_params KOpenPGPLayerParams_ECDSA_4 = {
	  "\x04\xda\xee\xa1\x23\x3f\x4d\xc6\x55\xf1\xe3\x6b\x54\x29\x50\x08\x40\x9e\x34\x6e\x3b\xa4\xd7\x4f\x00\xf8\x31\xff\xc3\x44\xbf\xd1\x64\x98\xee\x30\x77\x14\xce\x8e\x4e\xd3\xf5\x8c\xef\x95\xa4\x65\xb8\x5f\xde\x27\xf3\x54\x28\x57\xdb\x47\xf3\x21\x1e\x0a\x15\x21\xc7\xa1\xd7\xe6\x87\x81\x8e\x61\x4b\x13\x85\x9e\x0b\xb0\x80\xd6\xbf\xa0\x8e\xc4\xf0\xbe\x06\x50\x19\xea\x44\x3b\x18\x62\x83\xed\x40",
	  97,
	  "\x5a\x1d\xa9\xb1\xaf\x56\xca\xe4\xd0\x04\x61\x60\x70\xca\xec\x80\xc6\xee\x4b\xe7\x5b\x88\xf4\x25\xc8\x4c\x9f\xd4\xe8\x63\x69\x32\x9d\xdb\x6b\x1b\x37\x29\x47\xfa\xe5\x1b\x9e\xe9\x0b\xdd\x14\x80",
	  48,
	  "\xa0\x45\xea\x81\x09\xab\x21\xd7\x21\xf7\xd1\xa9\xf0\xfe\x07\x5d\x0f\x1d\x4f\x94\x18\xd5\x6f\x68\xcf\x50\x8c\xa7\x5d\x71\x8b\xf9\x9a\x8a\xed\x5d\x48\x26\x57\xab\x08\x49\x4e\x56\x75\x3d\xb7\x29\x2a\x75\x09\x19\x82\x54\xfa\x04\x35\x3f\xbd\x94\x9b\xb5\x0b\x56",
	  64,
	  "\x62\x0c\xf4\xad\x6d\xff\x7f\x42\x30\x5d\x7b\xf2\xa7\xc2\x28\x17\x52\xd0\x00\x3b\x0c\x80\xa2\xdb\x70\x50\x4b\x88\x8d\xd7\x0c\x44\xc3\x80\xba\x1d\x92\x3d\xc8\x56\x81\xb7\x10\x18\x52\x0f\x00\x7f",
	  48,
	  "\x6a\x27\x7f\x77\xfc\x30\x1f\x4f\x8c\x32\x2b\xbc\x38\x54\x09\xdf\x1a\x44\xf8\x7d\xe9\x40\xfb\x1c\x90\xf7\x74\x68\x55\x97\x71\x18\x40\x53\x94\x23\xbb\x56\x1a\x2b\x7d\x3a\xac\xcf\x70\x44\xe3\x5a",
	  48,
	  "\x74\xbd\xd1\x22\x07\x34\xc5\x77\xdc\x05\x34\x56\x67\x5d\xcb\xfb\x1a\xa3\x55\xf7\x3e\x8c\xba\x89\x98\xcb\x3f\xea\x0e\xaf\x5d\xf0\xbf\x74\xd5\x61\x06\x99\xdc\xa7\xb2\xda\x5e\xc3\x96\x11\x50\x45",
	  48,
	  SECP384R1,
	  SHA512
};

const ecdsa_params KOpenPGPLayerParams_ECDSA_5 = {
	  "\x04\xda\xee\xa1\x23\x3f\x4d\xc6\x55\xf1\xe3\x6b\x54\x29\x50\x08\x40\x9e\x34\x6e\x3b\xa4\xd7\x4f\x00\xf8\x31\xff\xc3\x44\xbf\xd1\x64\x98\xee\x30\x77\x14\xce\x8e\x4e\xd3\xf5\x8c\xef\x95\xa4\x65\xb8\x5f\xde\x27\xf3\x54\x28\x57\xdb\x47\xf3\x21\x1e\x0a\x15\x21\xc7\xa1\xd7\xe6\x87\x81\x8e\x61\x4b\x13\x85\x9e\x0b\xb0\x80\xd6\xbf\xa0\x8e\xc4\xf0\xbe\x06\x50\x19\xea\x44\x3b\x18\x62\x83\xed\x40",
	  97,
	  "\x5a\x1d\xa9\xb1\xaf\x56\xca\xe4\xd0\x04\x61\x60\x70\xca\xec\x80\xc6\xee\x4b\xe7\x5b\x88\xf4\x25\xc8\x4c\x9f\xd4\xe8\x63\x69\x32\x9d\xdb\x6b\x1b\x37\x29\x47\xfa\xe5\x1b\x9e\xe9\x0b\xdd\x14\x80",
	  48,
	  "\xf4\x27\x15\x55\xf7\xe1\x5e\xbc\xf0\x6c\xbe\xee\xc3\xaa\x37\xbd\x8d\xd8\x4f\x58\x00\xc4\x34\x9f\xe4\xef\xb3\xfb\x42\xda\xbc\xb6\x04\x99\x9d\x04\xd3\xfd\xd8\x61\x60\xbc\xfa\x8c\x0c\x0e\x26\x1e\x85\xb5\x0d\x47\x8a\xf2\x0d\x4d\x0a\x79\xcc\x1c\x2c\xed\xdd\xb2",
	  64,
	  "\x18\xc1\xcc\xae\xf0\xeb\x5d\x24\x3b\x1e\xd5\x59\x2c\xf2\x10\x04\xaf\x0d\xfb\x8c\x93\x64\x9c\xa9\x2a\xb1\xc9\x51\x92\xc7\xe2\x94\xd2\x3d\xfd\xe5\x4c\xaf\x5c\x80\x7e\x2d\x75\xf5\x06\xd1\x0f\x3a",
	  48,
	  "\xd9\x65\x48\x43\x45\xea\x27\xeb\x95\xd7\xbc\xc2\x3c\x67\xcd\x89\x67\x59\xd4\x3f\x76\xd2\x03\x70\x20\x58\x4c\x7b\x0a\xbf\xce\x66\x16\xfc\xf9\xbc\x08\x28\x5b\x1c\xcd\xf1\x09\xe6\xda\x46\x05\x0c",
	  48,
	  "\x1b\xbc\xe3\xe4\xc7\xcd\xd7\x9f\x81\xab\x91\xa5\xa7\x3d\xdb\x4c\x8d\x44\xec\x2d\x04\xe3\x2d\x55\xa1\xd4\x52\x16\x4f\x4a\xdd\xbb\x6a\xc8\xaa\xd9\x1f\x46\x2b\x9d\x86\xb8\x1b\x39\xa1\xd2\x0b\xa7",
	  48,
	  SECP384R1,
	  SHA512
};

const ecdsa_params KOpenPGPLayerParams_EdDSA_1 = {
	  "\x40\x5d\x71\x95\x9b\x62\x44\x7a\x63\xfc\x7d\x53\xf9\x7b\xc9\xdc\x6e\x3d\x13\xf1\xc5\x12\xf9\xbd\x1e\x08\x8e\xcf\x6f\x9f\xfb\x11\xc6",
	  33,
	  "\x67\xa9\x6b\x50\xa0\xb8\xe7\x8e\xd3\xc5\x40\x35\x57\x7f\x5d\x2b\x34\x16\xc0\x8b\x18\x54\x70\x97\x99\xdb\x93\xc4\x09\xa3\xbd\x53",
	  32,
	  "\x1e\x66\x59\x16\x2f\xd3\xd7\x9f\x3a\x26\xa9\x59\x6d\xf8\xab\x58\x6d\x5f\xc3\xd7\x95\x00\x71\x30\xe5\xdb\xd8\xd2\x47\xa3\x62\x12\x0a\x28\x29\xe3\xc1\x29\x98\xae\x45\xad\x3b\x6d\xb5\x0e\x0d\xe4\x5a\xe6\x54\x00\xac\xdf\xdf\xa1\x00\x79\x8d\xd5\x16\xb8\xf5\x6c",
	  64,
	  "",
	  0,
	  "\xdd\x59\x83\x67\xea\x91\x3a\x55\xb9\xf4\xbc\x4d\xf6\x7d\x69\xb9\x2d\x7f\x70\x68\xe9\x7b\xec\x6d\xa7\x52\xcb\xda\xba\x53\xed\x2c",
	  32,
	  "\x55\xb2\xa5\xb2\x8b\xbf\xa6\x78\x68\xdd\xdc\xef\x83\x7f\x3a\x9c\x26\x9c\xc3\xb0\x94\x8d\x2d\x30\x95\x70\x65\x46\x6d\x8a\xc0\x05",
	  32,
	  WEI25519,
	  SHA512
};

const ecdsa_params KOpenPGPLayerParams_EdDSA_2 = {
	  "\x40\x5d\x71\x95\x9b\x62\x44\x7a\x63\xfc\x7d\x53\xf9\x7b\xc9\xdc\x6e\x3d\x13\xf1\xc5\x12\xf9\xbd\x1e\x08\x8e\xcf\x6f\x9f\xfb\x11\xc6",
	  33,
	  "\x67\xa9\x6b\x50\xa0\xb8\xe7\x8e\xd3\xc5\x40\x35\x57\x7f\x5d\x2b\x34\x16\xc0\x8b\x18\x54\x70\x97\x99\xdb\x93\xc4\x09\xa3\xbd\x53",
	  32,
	  "\x49\x2d\x66\xd1\xca\xcf\xfe\x64\xeb\x90\xfe\x9a\x7c\x69\x18\x9c\xcc\xa6\x80\x1c\xb4\xe3\xa7\x45\x0c\x14\xe4\x5c\x11\xcf\x37\x75\x34\x7c\xac\x28\xab\xfb\x2a\xf2\x7a\x36\x0e\x96\x3d\xd5\x16\xc7\xd2\x5d\x08\x1e\x1b\xd4\xe9\x9d\x41\x97\xc5\xca\x11\x51\xb7\xef",
	  64,
	  "",
	  0,
	  "\xeb\x3a\x8c\x03\x2d\x13\xa5\x5c\x5b\x3f\x62\xc3\xec\xfa\xcf\x42\x6f\xc4\x37\x8c\x1d\xb6\x7a\x34\x3e\xbf\x38\x4e\x32\x9d\x86\xff",
	  32,
	  "\x73\x53\x69\xfc\x91\x3b\xa8\x5d\xbd\x8b\x04\xff\x88\x12\x34\x3f\x31\xba\x22\x91\x81\xa9\x85\x31\xd1\x9f\x47\x46\x61\x8b\x93\x05",
	  32,
	  WEI25519,
	  SHA512
};

#endif
