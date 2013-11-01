library hashes_murmur3;

import 'dart:typed_data';
import 'package:crypto/crypto.dart';

class Murmur3_32 extends Hash{
  final int blockSize = 32;
  
  int _hash = 0;
  int _length = 0;
  List<int> _rest = [];
  List<int> _done = null;
  
  Murmur3_32(List<int> seed){
    _hash = ((seed[0] & _B8)) |
        ((seed[1] & _B8) << 8) |
        ((seed[2] & _B8) << 16) |
        ((seed[3] & _B8) << 24);
  }
  
  void add(List<int> data){
    if(_done != null){
      throw new StateError('Can\'t call add() after close()');
    }
    _length += data.length;
    _rest.addAll(data);
    
    var k = 0;
    while(_rest.length >= 4){
      k = ((_rest[0] & _B8)) |
          ((_rest[1] & _B8) << 8) |
          ((_rest[2] & _B8) << 16) |
          ((_rest[3] & _B8) << 24);
      _rest.removeRange(0, 3);
      
      k = (k * _C1).toInt() & _B32;
      k = (k << _R1) | (k >> _R1_M);
      k = (k * _C2).toInt() & _B32;
      
      _hash ^= k;
      _hash = (_hash << _R2) | (_hash >> _R2_M);
      _hash = (_hash * _M + _N).toInt() & _B32;
    }
  }
  
  List<int> close(){
    var k = 0;
    if(_rest.length == 3){
      k ^= (_rest[_rest.length - 3] & _B8) << 16;
    }
    if(_rest.length >= 2){
      k ^= (_rest[_rest.length - 2] & _B8) << 8;
    }
    if(_rest.length >= 1){
      k ^= (_rest[_rest.length - 1] & _B8);
      k = (k * _C1).toInt() & _B32;
      k = (k << _R1) | (k >> _R1_M);
      k = (k * _C2).toInt() & _B32;
      
      _hash ^= k;
    }
    
    _hash ^= _length;
    _hash ^= (_hash >> 16);
    _hash = (_hash * 0x85ebca6b) & _B32;
    _hash ^= (_hash >> 13);
    _hash = (_hash * 0xc2b2ae35) & _B32;
    _hash ^= (_hash >> 16);
    
    return new Uint8List.view(new Uint32List.fromList([_hash]).buffer).toList();
  }
  
  Murmur3_32 newInstance() => new Murmur3_32._copy(_hash,_length,_rest);
  
  Murmur3_32._copy(this._hash,this._length,this._rest);
  
  static const _C1 = 0xcc9e2d51;
  static const _C2 = 0x1b873593;
  static const _R1 = 15;
  static const _R1_M = 32 - _R1;
  static const _R2 = 13;
  static const _R2_M = 32 - _R2;
  static const _M = 5;
  static const _N = 0xe6546b64;
  static const _B32 = 0xffffffff;
  static const _B8 = 0xff;
}