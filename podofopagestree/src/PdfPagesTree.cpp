/***************************************************************************
*   Copyright (C) 2006 by Dominik Seichter                                *
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

#include "PdfPagesTree.h"

#include "PdfArray.h"
#include "PdfDictionary.h"
#include "PdfObject.h"
#include "PdfOutputDevice.h"
#include "PdfPage.h"
#include "PdfVecObjects.h"

#include <iostream>
namespace PoDoFo {

PdfPagesTree::PdfPagesTree( PdfVecObjects* pParent )
    : PdfElement( "Pages", pParent )
{
    GetObject()->GetDictionary().AddKey( "Kids", PdfArray() ); // kids->Reference() 
    GetObject()->GetDictionary().AddKey( "Count", PdfObject( 0L ) );
}

PdfPagesTree::PdfPagesTree( PdfObject* pPagesRoot )
    : PdfElement( "Pages", pPagesRoot )
{
    if( !m_pObject ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    // pre-allocate enough elements
    // better performance and allows for a "sparse array"
    m_deqPageObjs.resize( GetTotalNumberOfPages() );
}

PdfPagesTree::~PdfPagesTree() 
{
    PdfPageList::iterator it = m_deqPageObjs.begin();

    while( it != m_deqPageObjs.end() )
    {
        delete (*it);
        ++it;
    }
        
    m_deqPageObjs.clear();
}

int PdfPagesTree::GetTotalNumberOfPages() const
{
    return ( ( m_pObject->GetDictionary().HasKey( "Count" ) ) ?
             m_pObject->GetDictionary().GetKeyAsLong( "Count", 0 ) : 0 );
}



PdfPage* PdfPagesTree::GetPage( int nIndex )
{
    const PdfObject* pObj;
    PdfPage*   pPage;

    // if you try to get a page past the end, return NULL
    // we use >= since nIndex is 0 based
    if ( nIndex >= GetTotalNumberOfPages() )
        return NULL;


    PdfObjectList lstParents;
    pObj = this->GetPageNode(nIndex, this->GetRoot(), lstParents);

    /*
    // if we already have the page in our list, return it
    // otherwise, we need to find it, add it and return it
    pPage = m_deqPageObjs[ nIndex ];
    if ( !pPage ) 
    {
    }
    */
    
    return pPage;
}

PdfPage* PdfPagesTree::GetPage( const PdfReference & ref )
{
    // We have to search through all pages,
    // as this is the only way
    // to instantiate the PdfPage with a correct list of parents
    for( int i=0;i<this->GetTotalNumberOfPages();i++ ) 
    {
        PdfPage* pPage = this->GetPage( i );
        if( pPage->GetObject()->Reference() == ref ) 
            return pPage;
    }
    
    return NULL;
}


void PdfPagesTree::InsertPage( int inAfterPageNumber, PdfPage* inPage )
{
    this->InsertPage( inAfterPageNumber, inPage->GetObject() );
}

void PdfPagesTree::InsertPage( int inAfterPageNumber, PdfObject* pPage )
{
}


PdfPage* PdfPagesTree::CreatePage( const PdfRect & rSize )
{

}

void PdfPagesTree::DeletePage( int inPageNumber )
{

}


////////////////////////////////////////////////////
// Private methods
////////////////////////////////////////////////////

const PdfObject* PdfPagesTree::GetPageNode( int nPageNum, PdfObject* pParent, 
                                            PdfObjectList & rLstParents ) const 
{
    if( !pParent ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    if( !pParent->GetDictionary().HasKey( "Kids" ) )
    {
        return NULL;
    }

    const PdfObject* pObj = pParent->GetDictionary().GetKey( "Kids" );
    if( !pObj->IsArray() )
    {
        return NULL;
    }

    const PdfArray & rKidsArray = pObj->GetArray(); 
    PdfArray::const_iterator it = rKidsArray.begin();

    const size_t numDirectKids = rKidsArray.size();
    const size_t numKinds = pParent->GetDictionary().GetKeyAsLong( "Count", 0L );

    if( numDirectKids == numKinds )
    {
        // This node has only page nodes as kids,
        // so we can access the array directly
        rLstParents.push_back( pParent );
        return GetPageNodeFromArray( nPageNum, rKidsArray, rLstParents );
    } 
    else
    {
        // We have to traverse the tree
        while( it != rKidsArray.end() ) 
        {
            if( (*it).IsArray() ) 
            {
                // Fixes some broken PDFs who have trees with 1 element kids arrays
                
            }
            else if( (*it).IsReference() ) 
            {
                PdfObject* pChild = GetRoot()->GetOwner()->GetObject( (*it).GetReference() );
                if (!pChild) 
                {
                    PdfError::LogMessage( eLogSeverity_Critical, "Requesting page index %i. Child not found: %s\n", 
                                          nPageNum, (*it).GetReference().ToString().c_str()); 
                    return NULL;
                }

                int childCount = this->GetChildCount( pChild );
                if( childCount < nPageNum ) 
                {
                    // skip this page node
                    // and go to the next one
                    nPageNum -= childCount;
                }
                else
                {
                    rLstParents.push_back( pParent );
                    return this->GetPageNode( nPageNum, pChild, rLstParents );
                }
            }
            else
            {
                PdfError::LogMessage( eLogSeverity_Critical, "Requesting page index %i. Invalid datatype in kids array: %s\n", 
                                      nPageNum, (*it).GetDataTypeString()); 
                return NULL;
            }
            
            ++it;
        }
    }


    return NULL;
}

const PdfObject* PdfPagesTree::GetPageNodeFromArray( int nPageNum, const PdfArray & rKidsArray, PdfObjectList & rLstParents ) const
{
    if ( static_cast<size_t>(nPageNum) >= rKidsArray.GetSize() )
    {
        PdfError::LogMessage( eLogSeverity_Critical, "Requesting page index %i from array of size %i\n", 
                              nPageNum, rKidsArray.size() );
        return NULL;
    }

    PdfVariant rVar = rKidsArray[nPageNum];
    while ( true ) 
    {
        if ( rVar.IsArray() ) 
        {
            // Fixes some broken PDFs who have trees with 1 element kids arrays
            return GetPageNodeFromArray( nPageNum, rVar.GetArray(), rLstParents );
        }
        else if ( !rVar.IsReference() )
            return NULL;	// can't handle inline pages just yet...

        PdfObject* pgObject = GetRoot()->GetOwner()->GetObject( rVar.GetReference() );
        
        // make sure the object is a /Page and not a /Pages with a single kid
        if( this->IsTypePage(pgObject) ) 
        {
            return pgObject;
        }

        // it's a /Pages with a single kid, so dereference and try again...
        if (this->IsTypePages(pgObject) ) 
        {
            if( !pgObject->GetDictionary().HasKey( "Kids" ) )
                return NULL;

            rLstParents.push_back( pgObject );
            rVar = *(pgObject->GetDictionary().GetKey( "Kids" ));
        }
    }

    return NULL;
}

bool PdfPagesTree::IsTypePage(const PdfObject* pObject) const 
{
    if( !pObject )
        return false;

    if( pObject->GetDictionary().GetKeyAsName( PdfName( "Type" ) ) == PdfName( "Page" ) )
        return true;

    return false;
}

bool PdfPagesTree::IsTypePages(const PdfObject* pObject) const 
{
    if( !pObject )
        return false;

    if( pObject->GetDictionary().GetKeyAsName( PdfName( "Type" ) ) == PdfName( "Pages" ) )
        return true;

    return false;
}

int PdfPagesTree::GetChildCount( const PdfObject* pNode ) const
{
    if( !pNode ) 
        return 0;

    return static_cast<int>(pNode->GetDictionary().GetKeyAsLong("Count", 0L));
}

/*
PdfObject* PdfPagesTree::GetPageNode( int nPageNum, PdfObject* pPagesObject, 
                                      std::deque<PdfObject*> & rListOfParents )
{
    // recurse through the pages tree nodes
    PdfObject* pObj            = NULL;

    if( !pPagesObject->GetDictionary().HasKey( "Kids" ) )
        return NULL;

    pObj = pPagesObject->GetDictionary().GetKey( "Kids" );
    if( !pObj->IsArray() )
        return NULL;

    PdfArray&	kidsArray = pObj->GetArray();
    size_t	numKids   = kidsArray.size();
    size_t      kidsCount = pPagesObject->GetDictionary().GetKeyAsLong( "Count", 0 );

    // All parents of the page node will be added to this lists,
    // so that the PdfPage can later access inherited attributes
    rListOfParents.push_back( pPagesObject );

    // the pages tree node represented by pPagesObject has only page nodes in its kids array,
    // or pages nodes with a kid count of 1, so we can speed things up
    // by going straight to the desired node
    if ( numKids == kidsCount )
    {
        if( nPageNum >= static_cast<int>(kidsArray.size()) )
        {
            PdfError::LogMessage( eLogSeverity_Critical, "Requesting page index %i from array of size %i\n", nPageNum, kidsArray.size() );
            nPageNum--;
        }

        PdfVariant pgVar = kidsArray[ nPageNum ];
        while ( true ) 
        {
            if ( pgVar.IsArray() ) 
            {
                // Fixes some broken PDFs who have trees with 1 element kids arrays
                return GetPageNodeFromTree( nPageNum, pgVar.GetArray(), rListOfParents );
            }
            else if ( !pgVar.IsReference() )
                return NULL;	// can't handle inline pages just yet...

            PdfObject* pgObject = GetRoot()->GetOwner()->GetObject( pgVar.GetReference() );
            // make sure the object is a /Page and not a /Pages with a single kid
            if ( pgObject->GetDictionary().GetKeyAsName( PdfName( "Type" ) ) == PdfName( "Page" ) )
                return pgObject;

            // it's a /Pages with a single kid, so dereference and try again...
            if( !pgObject->GetDictionary().HasKey( "Kids" ) )
                return NULL;

            rListOfParents.push_back( pgObject );
            pgVar = *(pgObject->GetDictionary().GetKey( "Kids" ));
        }
    } 
    else 
    {
        return GetPageNodeFromTree( nPageNum, kidsArray, rListOfParents );
    }

    // we should never exit from here - we should always have been able to return a page from above
    // assert( false ) ;
    return NULL;
}
*/

};
