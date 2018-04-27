# -*- coding: utf-8 -*-

# https://tools.ietf.org/html/rfc4880#section-4.3
tags = {
    0:  "Reserved",
    1:  "Public-Key Encrypted Session Key Packet",
    2:  "Signature Packet",
    3:  "Symmetric-Key Encrypted Session Key Packet",
    4:  "One-Pass Signature Packet",
    5:  "Secret-Key Packet",
    6:  "Public-Key Packet",
    7:  "Secret-Subkey Packet",
    8:  "Compressed Data Packet",
    9:  "Symmetrically Encrypted Data Packet",
    10: "Marker Packet",
    11: "Literal Data Packet",
    12: "Trust Packet",
    13: "User ID Packet",
    14: "Public-Subkey Packet",
    17: "User Attribute Packet",
    18: "Sym. Encrypted and Integrity Protected Data Packet",
    19: "Modification Detection Code Packet",
}

def lookup_tag(tag):
    if tag in (60, 61, 62, 63):
        return "Private or Experimental Values"
    return tags.get(tag, "Unknown")


# Specification: https://tools.ietf.org/html/rfc4880#section-5.2
pub_algorithms = {
    1:  "RSA Encrypt or Sign",
    2:  "RSA Encrypt-Only",
    3:  "RSA Sign-Only",
    #16: "ElGamal Encrypt-Only",
    17: "DSA Digital Signature Algorithm", 
    18: "Elliptic Curve", 
    19: "ECDSA", 
    #20: "Formerly ElGamal Encrypt or Sign",
    #21: "Diffie-Hellman", # future plans
}

def lookup_pub_algorithm(alg):
    if 100 <= alg <= 110:
        return "Private/Experimental algorithm"
    return pub_algorithms.get(alg, "Unknown")
