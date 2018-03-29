#!/usr/bin/env python3
from logging import debug, info, error, basicConfig, INFO, DEBUG
from struct import pack, unpack


# First, we define some utility functions so we only need to weite them once
"""
Takes an IP in quad dotted notation and converts it to bytes
"""
def str_to_ip(ip):
    return b"".join([bytes([int(x)]) for x in ip.split(".")])

"""
Takes bytes representing an IP address, and returns it in quad dotted notation
"""
def ip_to_str(b):
    return ".".join([str(int(x)) for x in b])

"""
Takes a bluetooth address in a string of colon delimited hex values and
converts it into a binary string.
"""
def str_to_bt(bt):
	return b"".join([bytes([int(x, 16)]) for x in bt.split(":")])

"""
Takes a binary string of bytes and converts them into a human readable
colon delimitied string of hex values.
"""
def bt_to_str(bt):
    return ":".join(["%0.2x" % x for x in bt])


"""
This class is to represent the "End of list" marker
"""
class End:
	pass
END_OBJECT=End()


"""
Extract data from a stream.

:param data: The data to extract from
:type data: bytestring
:returns: Tuple of Object extracted, and remaining data
:rtype: Tuple (object, bytestring)
"""
def extract_data(data):
	type_data = data[0] >> 4
	if type_data == 0:    # Null
		debug("Detected Null")
		return None, data[1:]
	elif type_data == 1:  # Boolean
		debug("Detected Boolean")
		return True, data[1:] if data[0] & 0xF0 else False, data[1:]
	elif type_data == 2:  # Integer
		length = data[0] & 0x0F
		debug("Detected int, length: %d" % length)
		if length == 1:
			return unpack(">B", data[1:2])[0], data[2:]
		elif length == 2:
			return unpack(">H", data[1:3])[0], data[3:]
		elif length == 4:
			return unpack(">I", data[1:5])[0], data[5:]
		elif length == 8:
			return unpack(">Q", data[1:9])[0], data[9:]
	elif type_data == 3:  # Float
		raise Exception("Float not implemented")
	elif type_data == 4:  # String
		raise Exception("String not implemented")
	elif type_data == 5:  # Raw
		# Type is 5n where n is the length-of-length (1, 2, 4, or 8)
		# We change the type to be an int and read that in as the length
		length, remainder = extract_data(bytes([data[0]&0x0F|0x20])+data[1:])
		debug("Raw data found with length: %d" % length)
		return remainder[:length], remainder[length:]
	elif type_data == 6:  # List
		debug("List detected")
		return _extract_list([], data[1:])
	elif type_data == 7:  # Dictionary
		raise Exception("Dictionary not implemented")
	elif type_data == 8:  # End
		debug("Detected end of list")
		return END_OBJECT, data[1:]
	raise Exception()

def _get_length_of_int(i):
	if i < 2**8:
		return 1
	if i < 2**16:
		return 2
	if i < 2**32:
		return 4
	if i < 2**64:
		return 8
	raise Exception("Can not handle intergers over 64-bits")
	
"""
Encodes data into the BDF format.  This does not base64 encode anything.

:param data: Data to be encoded
:type data: Python List
:returns: encoded data
:rtype: binary string
"""
def encode_data(data):
	if data is None:
		debug("Encoding Null")
		return b"\x00"  # Type = 0, value = 0
	if type(data) == bool:
		debug("Encoding Boolean")
		if data:
			return b"\x11"
		return b"\x10"
	if type(data) == int:
		length = _get_length_of_int(data)
		if length == 1:
			return pack(">B", 0x20 + length) + pack(">B", data)
		if length == 2:
			return pack(">B", 0x20 + length) + pack(">H", data)
		if length == 4:
			return pack(">B", 0x20 + length) + pack(">I", data)
		if length == 8:
			return pack(">B", 0x20 + length) + pack(">Q", data)
		raise Exception("Can not encode intergers over 64-bits")
	elif type(data) == float:
		raise Exception("Float not implemented")
	elif type(data) == str:
		raise Exception("String not implemented")
	elif type(data) == bytes:
		# type = 0x50, next 4 bits is the length-of-length (1, 2, 4, or 8), followed
		# by that number of bytes (as an encoded int, but without the type info),
		# followed by the actual data bytes
		return pack(">B", 0x50 + _get_length_of_int(len(data))) + encode_data(len(data))[1:] + data
	elif type(data) == list:
		debug("Encoding list")
		retval = b"\x60"
		for item in data:
			debug("Encoding list item: type=" + str(type(item)) + " value=" + str(item))
			retval += encode_data(item)
		return retval + b"\x80"  # 0x80 == END OF LIST
	elif type(data) == dict:
		raise Exception("Dictionary not implemented")
	raise Exception()

def _extract_list(list_data, data):
	debug("List contains: %s" % repr(list_data))
	obj, remainder = extract_data(data)
	debug("Extracted: %s" % obj)
	if obj == END_OBJECT:
		return list_data, remainder
	list_data.append(obj)
	return _extract_list(list_data, remainder)
