/*
  Stockfish, a UCI chess playing engine derived from Glaurung 2.1
  Copyright (C) 2004-2008 Tord Romstad (Glaurung author)
  Copyright (C) 2008-2014 Marco Costalba, Joona Kiiski, Tord Romstad

  Stockfish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Stockfish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PSQTAB_H_INCLUDED
#define PSQTAB_H_INCLUDED

#include "types.h"

#define S(mg, eg) make_score(mg, eg)


/// PSQT[PieceType][Square] contains Piece-Square scores. For each piece type on
/// a given square a (middlegame, endgame) score pair is assigned. PSQT is defined
/// for the white side and the tables are symmetric for the black side.

static const Score PSQT[][SQUARE_NB] = {
  { },
  { // Pawn
   S(  0, 0), S( 0, 0), S( 0, 0), S( 0, 0), S(0,  0), S( 0, 0), S( 0, 0), S(  0, 0),
   S(-20,-8), S(-6,-8), S( 4,-8), S(14,-8), S(14,-8), S( 4,-8), S(-6,-8), S(-20,-8),
   S(-20,-8), S(-6,-8), S( 9,-8), S(34,-8), S(34,-8), S( 9,-8), S(-6,-8), S(-20,-8),
   S(-20,-8), S(-6,-8), S(17,-8), S(54,-8), S(54,-8), S(17,-8), S(-6,-8), S(-20,-8),
   S(-20,-8), S(-6,-8), S(17,-8), S(34,-8), S(34,-8), S(17,-8), S(-6,-8), S(-20,-8),
   S(-20,-8), S(-6,-8), S( 9,-8), S(14,-8), S(14,-8), S( 9,-8), S(-6,-8), S(-20,-8),
   S(-20,-8), S(-6,-8), S( 4,-8), S(14,-8), S(14,-8), S( 4,-8), S(-6,-8), S(-20,-8),
   S(  0, 0), S( 0, 0), S( 0, 0), S( 0, 0), S(0,  0), S( 0, 0), S( 0, 0), S(  0, 0)
  },
  { // Knight
   S(-135,-104), S(-107,-79), S(-80,-55), S(-67,-42), S(-67,-42), S(-80,-55), S(-107,-79), S(-135,-104),
   S( -93, -79), S( -67,-55), S(-39,-30), S(-25,-17), S(-25,-17), S(-39,-30), S( -67,-55), S( -93, -79),
   S( -53, -55), S( -25,-30), S(  1, -6), S( 13,  5), S( 13,  5), S(  1, -6), S( -25,-30), S( -53, -55),
   S( -25, -42), S(   1,-17), S( 27,  5), S( 41, 18), S( 41, 18), S( 27,  5), S(   1,-17), S( -25, -42),
   S( -11, -42), S(  13,-17), S( 41,  5), S( 55, 18), S( 55, 18), S( 41,  5), S(  13,-17), S( -11, -42),
   S( -11, -55), S(  13,-30), S( 41, -6), S( 55,  5), S( 55,  5), S( 41, -6), S(  13,-30), S( -11, -55),
   S( -53, -79), S( -25,-55), S(  1,-30), S( 13,-17), S( 13,-17), S(  1,-30), S( -25,-55), S( -53, -79),
   S(-193,-104), S( -67,-79), S(-39,-55), S(-25,-42), S(-25,-42), S(-39,-55), S( -67,-79), S(-193,-104)
  },
  { // Bishop
   S(-40,-59), S(-40,-42), S(-35,-35), S(-30,-26), S(-30,-26), S(-35,-35), S(-40,-42), S(-40,-59),
   S(-17,-42), S(  0,-26), S( -4,-18), S(  0,-11), S(  0,-11), S( -4,-18), S(  0,-26), S(-17,-42),
   S(-13,-35), S( -4,-18), S(  8,-11), S(  4, -4), S(  4, -4), S(  8,-11), S( -4,-18), S(-13,-35),
   S( -8,-26), S(  0,-11), S(  4, -4), S( 17,  4), S( 17,  4), S(  4, -4), S(  0,-11), S( -8,-26),
   S( -8,-26), S(  0,-11), S(  4, -4), S( 17,  4), S( 17,  4), S(  4, -4), S(  0,-11), S( -8,-26),
   S(-13,-35), S( -4,-18), S(  8,-11), S(  4, -4), S(  4, -4), S(  8,-11), S( -4,-18), S(-13,-35),
   S(-17,-42), S(  0,-26), S( -4,-18), S(  0,-11), S(  0,-11), S( -4,-18), S(  0,-26), S(-17,-42),
   S(-17,-59), S(-17,-42), S(-13,-35), S( -8,-26), S( -8,-26), S(-13,-35), S(-17,-42), S(-17,-59)
  },
  { // Rook
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3),
   S(-12, 3), S(-7, 3), S(-2, 3), S(2, 3), S(2, 3), S(-2, 3), S(-7, 3), S(-12, 3)
  },
  { // Queen
   S(8,-80), S(8,-54), S(8,-42), S(8,-30), S(8,-30), S(8,-42), S(8,-54), S(8,-80),
   S(8,-54), S(8,-30), S(8,-18), S(8, -6), S(8, -6), S(8,-18), S(8,-30), S(8,-54),
   S(8,-42), S(8,-18), S(8, -6), S(8,  6), S(8,  6), S(8, -6), S(8,-18), S(8,-42),
   S(8,-30), S(8, -6), S(8,  6), S(8, 18), S(8, 18), S(8,  6), S(8, -6), S(8,-30),
   S(8,-30), S(8, -6), S(8,  6), S(8, 18), S(8, 18), S(8,  6), S(8, -6), S(8,-30),
   S(8,-42), S(8,-18), S(8, -6), S(8,  6), S(8,  6), S(8, -6), S(8,-18), S(8,-42),
   S(8,-54), S(8,-30), S(8,-18), S(8, -6), S(8, -6), S(8,-18), S(8,-30), S(8,-54),
   S(8,-80), S(8,-54), S(8,-42), S(8,-30), S(8,-30), S(8,-42), S(8,-54), S(8,-80)
  },
  { // King
   S(298, 27), S(332, 81), S(273,108), S(225,116), S(225,116), S(273,108), S(332, 81), S(298, 27),
   S(287, 74), S(321,128), S(262,155), S(214,163), S(214,163), S(262,155), S(321,128), S(287, 74),
   S(224,111), S(258,165), S(199,192), S(151,200), S(151,200), S(199,192), S(258,165), S(224,111),
   S(196,135), S(230,189), S(171,216), S(123,224), S(123,224), S(171,216), S(230,189), S(196,135),
   S(173,135), S(207,189), S(148,216), S(100,224), S(100,224), S(148,216), S(207,189), S(173,135),
   S(146,111), S(180,165), S(121,192), S( 73,200), S( 73,200), S(121,192), S(180,165), S(146,111),
   S(119, 74), S(153,128), S( 94,155), S( 46,163), S( 46,163), S( 94,155), S(153,128), S(119, 74),
   S( 98, 27), S(132, 81), S( 73,108), S( 25,116), S( 25,116), S( 73,108), S(132, 81), S( 98, 27)
  }
};

#undef S

#endif // #ifndef PSQTAB_H_INCLUDED
