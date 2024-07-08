package main

import (
    "fmt"
    "hash/crc32"
)

func main() {
    // Binary representation of 'A' (01000001 01000001)
    binA := []byte{0x41, 0x41}

    // Binary representation of 'B' (01000010 01000010)
    binB := []byte{0x42, 0x42}

    // Calculate XOR of the bytes
    xor := make([]byte, len(binA))
    for i := 0; i < len(binA); i++ {
        xor[i] = binA[i] ^ binB[i]
    }

    fmt.Printf("XOR result binary: %08b %08b\n", xor[0], xor[1])

    // Calculate CRC32 checksums for 'A', 'B', and their XOR
    checksum1 := crc32.ChecksumIEEE(binA)
    fmt.Printf("CRC32 checksum for 'A' in binary: %032b\n", checksum1)

    checksum2 := crc32.ChecksumIEEE(binB)
    fmt.Printf("CRC32 checksum for 'B' in binary: %032b\n", checksum2)

    // Add the hex value 0x0000 as 2 bytes
    hex := []byte{0x00, 0x00}
    fmt.Printf("Hex value: %x\n", hex)

    // Calculate CRC32 checksum for the hex value
    checksum_hex := crc32.ChecksumIEEE(hex)
    fmt.Printf("CRC32 checksum for hex value in binary: %032b\n", checksum_hex)

    checksum3 := crc32.ChecksumIEEE(xor)
    fmt.Printf("CRC32 checksum for XOR result in binary: %032b\n", checksum3)

    // Calculate XOR of the checksums for 'A', 'B', and the hex value
    xor_result := checksum1 ^ checksum2 ^ checksum_hex
    fmt.Printf("XOR of CRC32 checksums in binary: %032b\n", xor_result)

    // Check if the checksum of the XOR is equal to the XOR of the checksums
    if checksum3 == xor_result {
        fmt.Println("CRC(A) XOR CRC(B) XOR CRC(hex) == CRC(A XOR B)")
    } else {
        fmt.Println("CRC(A) XOR CRC(B) XOR CRC(hex) != CRC(A XOR B)")
    }
}