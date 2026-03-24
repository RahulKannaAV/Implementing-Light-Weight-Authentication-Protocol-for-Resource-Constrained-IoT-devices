hex_str = "b86fe55de704d8d42af0856e84a4a1481e987490fa4414dda83295862cc799d2 "
r0 = 123  # must be 0–255

bytes_arr = bytes.fromhex(hex_str)
result = bytes([b ^ r0 for b in bytes_arr])

print(result.hex())


