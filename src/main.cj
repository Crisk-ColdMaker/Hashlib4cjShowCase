package CJPAD

import std.fs.*
import encoding.hex.*
import hashlib4cj.crypto.sha3.echo.*
import hashlib4cj.crypto.snefru.*
import hashlib4cj.hash32.AP
import hashlib4cj.checksum.crc_32.*
import hashlib4cj.crypto.Gost

main(): Unit {
    println("-----------------------------单次哈希-----------------------------")
    let echo = Echo256()
    let res1 = echo.computeStringUTF8("hashlib4cj")
    // 多种输出格式
    println("-> one time: ${res1}")
    println("one time hashCode: ${res1.getHashCode()}")
    println("one time Int64: ${res1.getInt64()}")
    //...

    println("-----------------------------增量哈希-----------------------------")
    echo.initialize()
    let input = "hashlib4cj".toArray()
    println("-> size : ${input.size}")
    for (part in input) {
        echo.transformByte(part)
    }
    let res2 = echo.transformFinal()
    println("-> multi times: ${res2}")

    // 多种数据类型
    echo.initialize()
    for (part in [[1, 2, 3, 4, 5],[6, 7, 8, 9, 10]]) {
        for (part2 in "hashlib4cj".toArray()) {
            echo.transformByte(part2)
            echo.transformInt64s(part)
        }
    }
    let res3 = echo.transformFinal()
    println("multi times add Int64: ${res3}")

    println("-----------------------------正确性验证-----------------------------")
    echo.initialize()
    let testResult = echo.computeBytes(fromHexString("3197").getOrThrow())
    if (testResult.toString() == "3678C17756C785582EF6691EE90CD64FAC942A0371D702A55BAF9B6DA2E14F87") {
        println("-> Echo256 test passed")
    } else {
        println("Echo256 test failed: ${testResult}")
    }

    println("-----------------------------共计88种哈希算法-----------------------------")
    println("Echo384: ${Echo384().computeStringUTF8("hashlib4cj")}")
    println("Snefru256: ${SnefruRounds4Size256().computeStringUTF8("hashlib4cj")}")
    println("AP: ${AP().computeStringUTF8("hashlib4cj")}")
    println("CRC32: ${CRC32IEEE().computeStringUTF8("hashlib4cj")}")
    //..

    println("-----------------------------部分API-----------------------------")
    let gost = Gost()
    println("-> Gost Any: ${gost.computeAny("hashlib4cj")}")
    println("-> Gost String: ${gost.computeStringUTF8("hashlib4cj")}")
    gost.transformAny("hashlib4cj")
    println("-> Gost transform String: ${gost.transformFinal()}")
    
    try (file = File(Path("./src/testFile.txt"), Read)) {
        println("Gost File: ${gost.computeFileFromPath(file.info.path, 0, file.info.size)}")
    }
    println("Gost Rune: ${gost.computeRune(r'a')}")
    println("Gost UInt16: ${gost.computeUInt16(0x1234)}")
    println("Gost UInt32: ${gost.computeUInt32(0x12345678)}")
    println("Gost UInt64: ${gost.computeUInt64(0x1234567890abcdef)}")

    println("Gost Int16: ${gost.computeInt16(-0x1234)}")
    println("Gost Int32: ${gost.computeInt32(-0x12345678)}")
    println("Gost Int64: ${gost.computeInt64(-0x1234567890abcdef)}")

    println("Gost Float32: ${gost.computeFloat32(3.14)}")
    println("Gost Float64: ${gost.computeFloat64(3.14)}")

    println("Gost Bytes: ${gost.computeBytes([0x12, 0x34, 0x56, 0x78])}")
    println("Gost UInt16s: ${gost.computeInt16s(Array<Int16>(10,repeat:0x1234))}")
    println("Gost UInt32s: ${gost.computeInt32s(Array<Int32>(10,repeat:0x12345678))}")
    //...

    println("-----------------------------错误处理-----------------------------")
    try {
        println("Gost Any: ${gost.computeAny(NotSupportClass())}")
    } catch (e: Exception) {
        println("${e}")
    }

    try {
        try (file = File(Path("./src/testFile.txt"), Read)) {
            println("Gost File: ${gost.computeFileFromPath(file.info.path, 0, file.info.size + 1)}")
        }
    } catch (e: Exception) {
        println("${e}")
    }
}

class NotSupportClass {}
