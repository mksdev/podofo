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
    : PdfIElement( "Page", pParent ), PdfCanvas()
{
    PdfVariant mediabox;
    rSize.ToVariant( mediabox );
    GetObject()->GetDictionary().AddKey( "MediaBox", mediabox );

    // The PDF specification suggests that we send all available PDF Procedure sets
    GetObject()->GetDictionary().AddKey( "Resources", PdfObject( PdfDictionary() ) );

    // XXX FIXME TODO Technically, nothing guarantees that the resources entry
    // is indirect.
    m_pResources = static_cast<PdfObject*>(GetObject()->GetIndirectKey( "Resources" ));
    m_pResources->GetDictionary().AddKey( "ProcSet", PdfCanvas::GetProcSet() );

    m_pContents = new PdfContents( pParent );
    GetObject()->GetDictionary().AddKey( PdfName::KeyContents, m_pContents->GetContents()->Reference());
}

PdfPage::PdfPage( PdfObject* pObject )
    : PdfIElement( "Page", pObject ), PdfCanvas()
{
    // XXX FIXME TODO Technically, nothing guarantees that the resources entry
    // is indirect.
    m_pResources = static_cast<PdfObject*>(GetObject()->GetIndirectKey( "Resources" ));
    // XXX FIXME TODO We can't safely assume that the passed object is really a PdfObject
    m_pContents = new PdfContents( static_cast<PdfObject*>(GetObject()->GetIndirectKey( "Contents" )) );
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

PdfRect PdfPage::CreateStandardPageSize( const EPdfPageSize ePageSize )
{
    PdfRect rect;

    switch( ePageSize ) 
    {
        case ePdfPageSize_A4:
            rect.SetWidth( 595.0 );
            rect.SetHeight( 842.0 );
            break;

        case ePdfPageSize_Letter:
            rect.SetWidth( 612.0 );
            rect.SetHeight( 792.0 );
            break;
            
        case ePdfPageSize_Legal:
            rect.SetWidth( 612.0 );
            rect.SetHeight( 1008.0 );
            break;
            
        case ePdfPageSize_A3:
            rect.SetWidth( 842.0 );
            rect.SetHeight( 1190.0 );
            break;

        case ePdfPageSize_Unknown:
        default:
            break;
    }

    return rect;
}

PdfVariant* PdfPage::GetInheritedKeyFromObject( const char* inKey, PdfObject* inObject ) const
{
    PdfVariant* pObj = NULL;

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
            // TODO we assume that if the object has a /Parent key it must be indirect.
            // Is this safe?
            pObj = GetInheritedKeyFromObject( inKey, static_cast<PdfObject*>(pObj) );
    }

    return pObj;
}

const PdfRect PdfPage::GetPageBox( const char* inBox ) const
{
    PdfRect      pageBox;

    // Take advantage of inherited values - walking up the tree if necessary
    // TODO iffy const_cast<>() here
    PdfVariant* pObj = GetInheritedKeyFromObject( inBox, const_cast<PdfObject*>(GetObject()) );

    // assign the value of the box from the array
    if ( pObj && pObj->IsArray() )
        pageBox.FromArray( pObj->GetArray() );

    return pageBox;
}

const int PdfPage::GetRotation() const 
{
    int rot = 0;

    // TODO iffy const_cast<>() here
    PdfVariant* pObj = GetInheritedKeyFromObject( "Rotate", const_cast<PdfObject*>(GetObject()) ); 
    if ( pObj && pObj->IsNumber() )
        rot = pObj->GetNumber();

    return rot;
}

PdfVariant* PdfPage::GetAnnotationsArray( bool bCreate ) const
{
    // check for it in the object itself
    if ( GetObject()->GetDictionary().HasKey( "Annots" ) ) 
    {
        // TODO iffy const_cast<>() here
        PdfVariant* pObj = const_cast<PdfVariant*>(GetObject()->GetIndirectKey( "Annots" ));
        if( pObj && pObj->IsArray() )
            return pObj;
    }
    else if( bCreate ) 
    {
        PdfArray array;
        const_cast<PdfPage*>(this)->GetObject()->GetDictionary().AddKey( "Annots", array );
        return const_cast<PdfVariant*>(GetObject()->GetDictionary().GetKey( "Annots" ));
    }

    return NULL;
}

const int PdfPage::GetNumAnnots() const
{
    const PdfVariant* pObj = this->GetAnnotationsArray();

    return pObj ? static_cast<int>(pObj->GetArray().size()) : 0;
}

PdfAnnotation* PdfPage::CreateAnnotation( EPdfAnnotation eType, const PdfRect & rRect )
{
    PdfAnnotation* pAnnot = new PdfAnnotation( this, eType, rRect, GetObject()->GetOwner() );
    PdfVariant*    pObj   = this->GetAnnotationsArray( true );
    // XXX FIXME TODO dangerous assumption that annotations will be indirect objects
    PdfReference   ref    = static_cast<PdfObject*>(pAnnot->GetObject())->Reference();

    pObj->GetArray().push_back( ref );
    m_mapAnnotations[ref] = pAnnot;

    return pAnnot;
}

PdfAnnotation* PdfPage::GetAnnotation( int index )
{
    PdfAnnotation* pAnnot;
    PdfReference   ref;

    PdfVariant*   pObj   = this->GetAnnotationsArray( false );

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
        pObj = GetObject()->GetOwner()->GetObject( ref );
        if( !pObj )
        {
            PODOFO_RAISE_ERROR( ePdfError_NoObject );
        }
     
        pAnnot = new PdfAnnotation( pObj );
        m_mapAnnotations[ref] = pAnnot;
    }

    return pAnnot;
}

void PdfPage::DeleteAnnotation( int index )
{
    PdfReference   ref;
    PdfVariant*    pObj   = this->GetAnnotationsArray( false );
    
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
    PdfVariant*        pObj   = this->GetAnnotationsArray( false );
    bool               bFound = false;

    // delete the annotation from the array

    if( !(pObj && pObj->IsArray()) )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    it = pObj->GetArray().begin();
    while( it != pObj->GetArray().begin() ) 
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
    delete GetObject()->GetOwner()->RemoveObject( ref );
}

unsigned int PdfPage::GetPageNumber() const
{
    unsigned int        nPageNumber = 0;
    // XXX FIXME TODO unsafe assumption that /Parent is an indirect object; iffy const cast
    PdfObject*         pParent      = static_cast<PdfObject*>(const_cast<PdfObject*>(GetObject())->GetIndirectKey( "Parent" ));
    PdfReference ref                = GetObject()->Reference();

    while( pParent ) 
    {
        const PdfArray& kids        = pParent->GetIndirectKey( "Kids" )->GetArray();
        PdfArray::const_iterator it = kids.begin();

        while( it != kids.end() && (*it).GetReference() != ref )
        {
            PdfObject* pNode = GetObject()->GetOwner()->GetObject( (*it).GetReference() );

            if( pNode->GetDictionary().GetKey( PdfName::KeyType )->GetName() == PdfName( "Pages" ) )
                nPageNumber += pNode->GetDictionary().GetKey( "Count" )->GetNumber();
            else 
                // if we do not have a page tree node, 
                // we most likely have a page object:
                // so the page count is 1
                ++nPageNumber;

            ++it;
        }

        ref     = pParent->Reference();
        // TODO FIXME XXX unsafe assumption that /Parent is an indirect object
        pParent = static_cast<PdfObject*>(pParent->GetIndirectKey( "Parent" ));
    }

    return ++nPageNumber;
}

};
