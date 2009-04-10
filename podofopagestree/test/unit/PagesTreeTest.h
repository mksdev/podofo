/***************************************************************************
 *   Copyright (C) 2008 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _PAGES_TREE_TEST_H_
#define _PAGES_TREE_TEST_H_

#include <cppunit/extensions/HelperMacros.h>

namespace PoDoFo {
class PdfMemDocument;
class PdfPage;
};

/** This test tests the class PdfPagesTree
 */
class PagesTreeTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE( PagesTreeTest );
  CPPUNIT_TEST( testEmptyTree );
  CPPUNIT_TEST( testEmptyDoc );
  CPPUNIT_TEST( testCreateDelete );
  CPPUNIT_TEST( testGetPages );
  CPPUNIT_TEST( testGetPagesReverse );
  CPPUNIT_TEST( testInsert );
  CPPUNIT_TEST( testDeleteAll );
  CPPUNIT_TEST_SUITE_END();

 public:
  void setUp();
  void tearDown();

  void testEmptyTree();
  void testEmptyDoc();
  void testCreateDelete();
  void testGetPages();
  void testGetPagesReverse();
  void testInsert();
  void testDeleteAll();
    
 private:
  /**
   * Create a pages tree with 100 pages,
   * where every page object has an additional
   * key PoDoFoTestPageNumber with the original 
   * page number of the page.
   *
   * You can check the page number ussing IsPageNumber()
   *
   * @see IsPageNumber
   */
  void CreateTestTree( PoDoFo::PdfMemDocument & rDoc );

  bool IsPageNumber( PoDoFo::PdfPage* pPage, int nNumber );
};

#endif // _PAGES_TREE_TEST_H_


