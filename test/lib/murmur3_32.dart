library hashes_murmur3_test;

import 'package:hashes/murmur3_32.dart';
import 'package:unittest/unittest.dart';

main() => group('Murmur3_32', (){
  test('returns a 32bit hash',(){
    var hash = new Murmur3_32([0,0,0,0]);
    hash.add('test'.codeUnits);
    expect(hash.close().length, 4);
  });
});