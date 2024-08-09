import json
import sys
import hashlib
import bencodepy
import requests
import urllib.parse


def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():  #checking if it's a string
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[: first_colon_index]) #string lenght
        return bencoded_value[first_colon_index + 1 : first_colon_index + 1 + length]
    elif bencoded_value.startswith(b"i") and bencoded_value.endswith(b"e"): #checking if it's integer
        int_value = bencoded_value[1:-1].decode()  # extract int value as string
        return int(int_value)   #convert back to integer
    elif bencoded_value.startswith(b"l") and bencoded_value.endswith(b"e"): #check if it's a list
        elements = []
        rest = bencoded_value[1 : -1]   #strip 'l' and 'e'
        while rest:
            element, rest = decode_next_element(rest)
            elements.append(element)
        return elements
    elif bencoded_value.startswith(b"d") and bencoded_value.endswith(b"e"): #check if it's a dictionary
        dict = {}
        rest = bencoded_value[1 : -1]   #strip 'd' and 'e'
        while rest:
            key, rest = decode_next_element(rest)
            if not isinstance(key, bytes):
                raise ValueError("dictionary keys must be string")
            value, rest = decode_next_element(rest)
            dict[key.decode()] = value  #decode key to string
        return dict
    else:
        raise NotImplementedError("Only strings, integers, lists, and dictionaries, are supported at the moment")

def decode_next_element(bencoded_value):
    if bencoded_value[0 : 1].isdigit():
        first_colon_index = bencoded_value.find(b":")
        length = int(bencoded_value[: first_colon_index])
        element = bencoded_value[first_colon_index + 1 : first_colon_index + 1 + length]
        rest = bencoded_value[first_colon_index + 1 + length :]
        return element, rest
    elif bencoded_value.startswith(b"i"):
        end_index = bencoded_value.find(b"e")
        int_value = int(bencoded_value[1 : end_index])
        rest = bencoded_value[end_index + 1 :]
        return int_value, rest
    elif bencoded_value.startswith(b"l"):
        elements = []
        rest = bencoded_value[1 :]  #strip 'l'
        while rest and not rest.startswith(b"e"):
            element, rest = decode_next_element(rest)
            elements.append(element)
        return element, rest[1:]    #strip 'e'
    elif bencoded_value.startswith(b"d"):
        dict = {}
        rest = bencoded_value[1:]   #strip 'd'
        while rest and not rest.startswith(b"e"):
            key, rest = decode_next_element(rest)
            value, rest = decode_next_element(rest)
            dict[key.decode()] = value
        return dict, rest[1:]   #strip 'e'
    else:
        raise ValueError("invalid bencoded value")

def format_as_bytes(data):
    if isinstance(data, bytes):
        return f"b'{data.decode()}'"
    elif isinstance(data, str):
        return f"b'{data}'"
    elif isinstance(data, list):
        return f"[{', '.join(format_as_bytes(item) for item in data)}]"
    elif isinstance(data, dict):
        return f"{{{', '.join(f'b{key} : {format_as_bytes(value)}' for key, value in data.items())}}}"
    else:
        return str(data)

def extract_torrent_info(bencoded_dict):
    if not isinstance(bencoded_dict, dict):
        raise ValueError("expected dictionary")
    announce = bencoded_dict.get('announce', None)
    info = bencoded_dict.get('info', None)
    if not info:
        raise ValueError("missing 'info' dictionary")
    lenght = info.get('length', None)
    return announce, lenght

def bencode(value):
    if isinstance(value, int):
        return f"i{value}e".encode()
    if isinstance(value, bytes):
        return f"{len(value)}:".encode() + value
    elif isinstance(value, str):
        value = value.encode()
        return f"{len(value)}".encode() + value
    elif isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    elif isinstance(value, dict):
        items = sorted(value.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    else:
        raise TypeError("unsupported type for bencoding")

def calc_info_hash(info_dict):
    bencoded_info = bencode(info_dict)
    return hashlib.sha1(bencoded_info).digest()

def get_peers_from_tracker(announce_url, info_hash, peer_id, file_length):
    parameters = {
        'info_hash' : urllib.parse.quote_plus(info_hash),
        'peer_id' : peer_id,
        'port' : 6881,
        'uploaded' : 0,
        'downloaded' : 0,
        'left' : file_length,
        'compact' : 1,
    }
    response = requests.get(announce_url, params=parameters)
    response.raise_for_status()
    tracker_response = decode_bencode(response.content)
    peers = tracker_response.get('peers')
    if peers:
        return parse_peers(peers)
    else:
        raise ValueError("No peers found in the tracker response")

def parse_peers(peers):
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = '.'.join(str(b) for b in peers[i : i + 4])
        port = int.from_bytes(peers[i + 4 : i + 6], 'big')
        peer_list.append((ip, port))
    return peer_list

def main():
    if len(sys.argv) < 3:
        print("Usage: script.py decode <bencoded_value>")
        sys.exit(1)
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        result = decode_bencode(bencoded_value)
        print("decoded value:", format_as_bytes(result))
    elif command == "torrent_info":
        file_path = sys.argv[2]
        with open(file_path, "rb") as f:
            bencoded_content = f.read()
        bencoded_dict = decode_bencode(bencoded_content)
        announce, length = extract_torrent_info(bencoded_dict)
        print(f"tracker URL: {announce}")
        print(f"file lenght : {length}")
    elif command == "info_hash":
        file_path = sys.argv[2]
        with open(file_path, "rb") as f:
            bencoded_content = f.read()
        bencoded_dict = decode_bencode(bencoded_content)
        info_dict = bencoded_dict['info']
        info_hash = calc_info_hash(info_dict)
        print(f"info hash : {info_hash}")
    elif command == "get_peers":
        file_path = sys.argv[2]
        with open(file_path, "rb") as f:
            bencoded_content = f.read()
        bencoded_dict = decode_bencode(bencoded_content)
        announce_url = bencoded_dict['announce']
        info_dict = bencoded_dict['info']
        info_hash = calc_info_hash(info_dict)
        peer_id = "00112233445566778899"
        file_length = info_dict['length']
        peers = get_peers_from_tracker(announce_url, info_hash, peer_id, file_length)
        print(f"Peers : {peers}")
    else:
        raise NotImplementedError(f"Unknown command {command}")



if __name__ == "__main__":
    main()
