import unittest
from main import decode_bencode, format_as_bytes, extract_torrent_info

class TestDecodeBencode(unittest.TestCase):
    def test_decode_string(self):
        result = decode_bencode(b'5:hello')
        print("Decoded string:", result)
        self.assertEqual(result, b'hello')

    def test_decode_integer(self):
        result = decode_bencode(b'i52e')
        print("Decoded integer:", result)
        self.assertEqual(result, 52)

    def test_decode_negative_integer(self):
        result = decode_bencode(b'i-52e')
        print("Decoded negative integer:", result)
        self.assertEqual(result, -52)

    def test_decode_list(self):
        result = decode_bencode(b'l5:helloi52ee')
        print("Decoded list:", result)
        self.assertEqual(result, [b'hello', 52])

    def test_decode_dict(self):
        result = decode_bencode(b'd3:foo3:bar5:helloi52ee')
        print("Decoded dictionary:", result)
        self.assertEqual(result, {'foo': b'bar', 'hello': 52})

    def test_extract_torrent_info(self):
        bencoded_dict = {
            'announce': b'http://bittorrent-test-tracker.codecrafters.io/announce',
            'info': {
                'length': 123045,
                'name': b'example_file.txt',
                'piece length': 16384,
                'pieces' : b'...'
            }
        }
        announce, lenght = extract_torrent_info(bencoded_dict)
        print(f"Tracker URL: {announce}")
        print(f"file lenght : {lenght}")
        # self.assertEqual(announce, b'http://bittorrent-test-tracker.codecrafters.io/announce')
        # self.assertEqual(lenght, 12345)

if __name__ == '__main__':
    unittest.main(verbosity=2)
