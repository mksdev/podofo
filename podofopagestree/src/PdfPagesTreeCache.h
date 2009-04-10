/***************************************************************************
*   Copyright (C) 2009 by Dominik Seichter                                *
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

#ifndef _PDF_PAGES_TREE_CACHE_H_
#define _PDF_PAGES_TREE_CACHE_H_

#include "PdfDefines.h"

namespace PoDoFo {

class PdfPage;

/**
 *  This class implements a cache infront of a PdfPagesTree
 *
 *  \see PdfCachedPagesTree
 */
class PODOFO_API PdfPagesTreeCache
{
	typedef std::map< int, PdfPage* > PdfPageMap;

 public:
    /** Construct a new PdfCachedPagesTree.
     */
    PdfPagesTreeCache();
    
    /** Close/down destruct a PdfCachedPagesTree
     */
    virtual ~PdfPagesTreeCache();

    /** Return a PdfPage for the specified Page index
     *  The returned page is owned by the pages tree and
     *  deleted along with it.
     *
     *  \param nIndex page index, 0-based
     *  \returns a pointer to the requested page or NULL if it is not cached
     */
    virtual PdfPage* GetPage( int nIndex );

    /**
     * Add a PdfPage to the cache
     * @param nIndex index of the page
     * @param pPage page object
     */
    virtual void AddPage( int nIndex, PdfPage* pPage );

    /**
     * Delete a PdfPage from the cache
     * @param nIndex index of the page
     */
    virtual void DeletePage( int nIndex );

    /**
     * Clear cache, i.e. remove all elements from the 
     * cache.
     */
    virtual void ClearCache();

private:
    PdfPageMap    m_mapPageObjs;
};

};

#endif // _PDF_PAGES_TREE_CACHE_H_


