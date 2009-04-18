/***************************************************************************
 *   Copyright (C) 2005 by Dominik Seichter                                *
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

#include "PdfPage.h" 
#include "PdfDictionary.h"
#include "PdfDocument.h"
#include "PdfRect.h"
#include "PdfVariant.h"
#include "PdfWriter.h"


namespace PoDoFo {

PdfPage::PdfPage( const PdfRect & rSize, PdfVecObjects* pParent )
    : PdfElement( "Page", pParent ), PdfCanvas()
{
    PdfVariant mediabox;
    rSize.ToVariant( mediabox );
    m_pObject->GetDictionary().AddKey( "MediaBox", mediabox );

    // The PDF specification suggests that we send all available PDF Procedure sets
    m_pObject->GetDictionary().AddKey( "Resources", PdfObject( PdfDictionary() ) );

    m_pResources = m_pObject->GetIndirectKey( "Resources" );
    m_pResources->GetDictionary().AddKey( "ProcSet", PdfCanvas::GetProcSet() );

    m_pContents = new PdfContents( pParent );
    m_pObject->GetDictionary().AddKey( PdfName::KeyContents, m_pContents->GetContents()->Reference());
}

PdfPage::PdfPage( PdfObject* pObject, const std::deque<PdfObject*> & rListOfParents )
    : PdfElement( "Page", pObject ), PdfCanvas()
{
    m_pResources = m_pObject->GetIndirectKey( "Resources" );
    if( !m_pResources ) 
    {
        // Resources might be inherited
        std::deque<PdfObject*>::const_reverse_iterator it = rListOfParents.rbegin();

        while( it != rListOfParents.rend() && !m_pResources )
        {
            m_pResources = (*it)->GetIndirectKey( "Resources" );
            ++it;
        }
    }

    PdfObject* pContents = m_pObject->GetIndirectKey( "Contents" );
    if (pContents)
        m_pContents = new PdfContents( pContents );
    else
    {
        // TODO: handle absent contents
        m_pContents = NULL;
    }
}

PdfPage::~PdfPage()
{
    TIMapAnnotation it = m_mapAnnotations.begin();

    while( it != m_mapAnnotations.end() )
    {
        delete (*it).second;

        ++it;
    }

    delete m_pContents;	// just clears the C++ object from memory, NOT the PdfObject
}

PdfRect PdfPage::CreateStandardPageSize( const EPdfPageSize ePageSize, bool bLandscape )
{
    PdfRect rect;

    switch( ePageSize ) 
    {
        case ePdfPageSize_A0:
            rect.SetWidth( 2384.0 );
            rect.SetHeight( 3370.0 );
            break;

        case ePdfPageSize_A1:
            rect.SetWidth( 1684.0 );
            rect.SetHeight( 2384.0 );
            break;

        case ePdfPageSize_A2:
            rect.SetWidth( 1191.0 );
            rect.SetHeight( 1684.0 );
            break;
            
        case ePdfPageSize_A3:
            rect.SetWidth( 842.0 );
            rect.SetHeight( 1190.0 );
            break;

        case ePdfPageSize_A4:
            rect.SetWidth( 595.0 );
            rect.SetHeight( 842.0 );
            break;

        case ePdfPageSize_A5:
            rect.SetWidth( 420.0 );
            rect.SetHeight( 595.0 );
            break;

        case ePdfPageSize_A6:
            rect.SetWidth( 297.0 );
            rect.SetHeight( 420.0 );
            break;

        case ePdfPageSize_Letter:
            rect.SetWidth( 612.0 );
            rect.SetHeight( 792.0 );
            break;
            
        case ePdfPageSize_Legal:
            rect.SetWidth( 612.0 );
            rect.SetHeight( 1008.0 );
            break;

        case ePdfPageSize_Tabloid:
            rect.SetWidth( 792.0 );
            rect.SetHeight( 1224.0 );
            break;

        default:
            break;
    }

    if( bLandscape ) 
    {
        double dTmp = rect.GetWidth();
        rect.SetWidth ( rect.GetHeight() );
        rect.SetHeight(  dTmp );
    }

    return rect;
}

PdfObject* PdfPage::GetInheritedKeyFromObject( const char* inKey, PdfObject* inObject ) const
{
    PdfObject* pObj = NULL;

    // check for it in the object itself
    if ( inObject->GetDictionary().HasKey( inKey ) ) 
    {
        pObj = inObject->GetDictionary().GetKey( inKey );
        if ( !pObj->IsNull() ) 
            return pObj;
    }
    
    // if we get here, we need to go check the parent - if there is one!
    if( inObject->GetDictionary().HasKey( "Parent" ) ) 
    {
        pObj = inObject->GetIndirectKey( "Parent" );
        if( pObj )
            pObj = GetInheritedKeyFromObject( inKey, pObj );
    }

    return pObj;
}

const PdfRect PdfPage::GetPageBox( const char* inBox ) const
{
    PdfRect	 pageBox;
    PdfObject*   pObj;
        
    // Take advantage of inherited values - walking up the tree if necessary
    pObj = GetInheritedKeyFromObject( inBox, m_pObject );
    
    // assign the value of the box from the array
    if ( pObj && pObj->IsArray() )
        pageBox.FromArray( pObj->GetArray() );
    
    return pageBox;
}

int PdfPage::GetRotation() const 
{ 
    int rot = 0;
    
    PdfObject* pObj = GetInheritedKeyFromObject( "Rotate", m_pObject ); 
    if ( pObj && pObj->IsNumber() )
        rot = static_cast<int>(pObj->GetNumber());
    
    return rot;
}

PdfObject* PdfPage::GetAnnotationsArray( bool bCreate ) const
{
    PdfObject* pObj;

    // check for it in the object itself
    if ( m_pObject->GetDictionary().HasKey( "Annots" ) ) 
    {
        pObj = m_pObject->GetIndirectKey( "Annots" );
        if( pObj && pObj->IsArray() )
            return pObj;
    }
    else if( bCreate ) 
    {
        PdfArray array;
        const_cast<PdfPage*>(this)->m_pObject->GetDictionary().AddKey( "Annots", array );
        return m_pObject->GetDictionary().GetKey( "Annots" );
    }

    return NULL;
}

int PdfPage::GetNumAnnots() const
{
    PdfObject* pObj = this->GetAnnotationsArray();

    return pObj ? static_cast<int>(pObj->GetArray().size()) : 0;
}

PdfAnnotation* PdfPage::CreateAnnotation( EPdfAnnotation eType, const PdfRect & rRect )
{
    PdfAnnotation* pAnnot = new PdfAnnotation( this, eType, rRect, m_pObject->GetOwner() );
    PdfObject*     pObj   = this->GetAnnotationsArray( true );
    PdfReference   ref    = pAnnot->GetObject()->Reference();

    pObj->GetArray().push_back( ref );
    m_mapAnnotations[ref] = pAnnot;

    return pAnnot;
}

PdfAnnotation* PdfPage::GetAnnotation( int index )
{
    PdfAnnotation* pAnnot;
    PdfReference   ref;

    PdfObject*     pObj   = this->GetAnnotationsArray( false );

    if( !(pObj && pObj->IsArray()) )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
    
    if( index < 0 && static_cast<unsigned int>(index) >= pObj->GetArray().size() )
    {
        PODOFO_RAISE_ERROR( ePdfError_ValueOutOfRange );
    }

    ref    = pObj->GetArray()[index].GetReference();
    pAnnot = m_mapAnnotations[ref];
    if( !pAnnot )
    {
        pObj = m_pObject->GetOwner()->GetObject( ref );
        if( !pObj )
        {
            PdfError::DebugMessage( "Error looking up object %i %i R\n", ref.ObjectNumber(), ref.GenerationNumber() );
            PODOFO_RAISE_ERROR( ePdfError_NoObject );
        }
     
        pAnnot = new PdfAnnotation( pObj, this );
        m_mapAnnotations[ref] = pAnnot;
    }

    return pAnnot;
}

void PdfPage::DeleteAnnotation( int index )
{
    PdfReference   ref;
    PdfObject*     pObj   = this->GetAnnotationsArray( false );
    
    if( !(pObj && pObj->IsArray()) )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
    
    if( index < 0 && static_cast<unsigned int>(index) >= pObj->GetArray().size() )
    {
        PODOFO_RAISE_ERROR( ePdfError_ValueOutOfRange );
    }

    ref    = pObj->GetArray()[index].GetReference();

    this->DeleteAnnotation( ref );
}

void PdfPage::DeleteAnnotation( const PdfReference & ref )
{
    PdfAnnotation*     pAnnot;
    PdfArray::iterator it;
    PdfObject*         pObj   = this->GetAnnotationsArray( false );
    bool               bFound = false;

    // delete the annotation from the array

    if( !(pObj && pObj->IsArray()) )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    it = pObj->GetArray().begin();
    while( it != pObj->GetArray().end() ) 
    {
        if( (*it).GetReference() == ref ) 
        {
            pObj->GetArray().erase( it );
            bFound = true;
            break;
        }

        ++it;
    }

    // if no such annotation was found
    // throw an error instead of deleting
    // another object with this reference
    if( !bFound ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_NoObject );
    }

    // delete any cached PdfAnnotations
    pAnnot = m_mapAnnotations[ref];
    if( pAnnot )
    {
        delete pAnnot;
        m_mapAnnotations.erase( ref );
    }

    // delete the PdfObject in the file
    delete m_pObject->GetOwner()->RemoveObject( ref );
}

unsigned int PdfPage::GetPageNumber() const
{
    unsigned int        nPageNumber = 0;
    PdfObject*          pParent     = m_pObject->GetIndirectKey( "Parent" );
    PdfReference ref                = m_pObject->Reference();

    while( pParent ) 
    {
        const PdfArray& kids        = pParent->GetIndirectKey( "Kids" )->GetArray();
        PdfArray::const_iterator it = kids.begin();

        while( it != kids.end() && (*it).GetReference() != ref )
        {
            PdfObject* pNode = m_pObject->GetOwner()->GetObject( (*it).GetReference() );

            if( pNode->GetDictionary().GetKey( PdfName::KeyType )->GetName() == PdfName( "Pages" ) )
                nPageNumber += static_cast<int>(pNode->GetDictionary().GetKey( "Count" )->GetNumber());
            else 
                // if we do not have a page tree node, 
                // we most likely have a page object:
                // so the page count is 1
                ++nPageNumber;

            ++it;
        }

        ref     = pParent->Reference();
        pParent = pParent->GetIndirectKey( "Parent" );
    }

    return ++nPageNumber;
}

int PdfPage::GetNumFields() const
{
    int                  nCount  = 0;
    int                  nAnnots = this->GetNumAnnots();
    const PdfAnnotation* pAnnot  = NULL;
    for( int i=0;i<nAnnots;i++ )
    {
        pAnnot = const_cast<PdfPage*>(this)->GetAnnotation( i );
        // Count every widget annotation with a FieldType as PdfField
        if( pAnnot->GetType() == ePdfAnnotation_Widget && 
            pAnnot->GetObject()->GetDictionary().HasKey( PdfName("FT") ) )
            ++nCount;
    }

    return nCount;
}

PdfField PdfPage::GetField( int index )
{
    int            nCount  = 0;
    int            nAnnots = this->GetNumAnnots();
    PdfAnnotation* pAnnot  = NULL;
    for( int i=0;i<nAnnots;i++ )
    {
        pAnnot = this->GetAnnotation( i );
        // Count every widget annotation with a FieldType as PdfField
        if( pAnnot->GetType() == ePdfAnnotation_Widget && 
            pAnnot->GetObject()->GetDictionary().HasKey( PdfName("FT") ) )
        {
            if( nCount == index )
            {
                return PdfField( pAnnot->GetObject(), pAnnot );
            }
            else
                ++nCount;
        }
    }

    PODOFO_RAISE_ERROR( ePdfError_ValueOutOfRange );
}

const PdfField PdfPage::GetField( int index ) const
{
    PdfField field = const_cast<PdfPage*>(this)->GetField( index );
    return field;
}

PdfObject* PdfPage::GetFromResources( const PdfName & rType, const PdfName & rKey )
{
    if( m_pResources->GetDictionary().HasKey( rType ) ) 
    {
        PdfObject* pType = m_pResources->GetDictionary().GetKey( rType );
        if( pType->IsDictionary() && pType->GetDictionary().HasKey( rKey ) )
        {
            const PdfReference & ref = pType->GetDictionary().GetKey( rKey )->GetReference();
            return m_pObject->GetOwner()->GetObject( ref );
        }
    }
    
    return NULL;
}

};
