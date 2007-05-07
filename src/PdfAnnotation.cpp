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

#include "PdfAnnotation.h"
#include "PdfAction.h"
#include "PdfArray.h"
#include "PdfDictionary.h"
#include "PdfDate.h"
#include "PdfFileSpec.h"
#include "PdfPage.h"
#include "PdfRect.h"
#include "PdfVariant.h"
#include "PdfXObject.h"

namespace PoDoFo {

const long  PdfAnnotation::s_lNumActions = 26;
const char* PdfAnnotation::s_names[] = {
    "Text",                       // - supported
    "Link",
    "FreeText",       // PDF 1.3  // - supported
    "Line",           // PDF 1.3  // - supported
    "Square",         // PDF 1.3
    "Circle",         // PDF 1.3
    "Polygon",        // PDF 1.5
    "PolyLine",       // PDF 1.5
    "Highlight",      // PDF 1.3
    "Underline",      // PDF 1.3
    "Squiggly",       // PDF 1.4
    "StrikeOut",      // PDF 1.3
    "Stamp",          // PDF 1.3
    "Caret",          // PDF 1.5
    "Ink",            // PDF 1.3
    "Popup",          // PDF 1.3
    "FileAttachment", // PDF 1.3
    "Sound",          // PDF 1.2
    "Movie",          // PDF 1.2
    "Widget",         // PDF 1.2  // - supported
    "Screen",         // PDF 1.5
    "PrinterMark",    // PDF 1.4
    "TrapNet",        // PDF 1.3
    "Watermark",      // PDF 1.6
    "3D",             // PDF 1.6
    NULL
};

PdfAnnotation::PdfAnnotation( PdfPage* pPage, EPdfAnnotation eAnnot, const PdfRect & rRect, PdfVecObjects* pParent )
    : PdfElement( "Annot", pParent ), m_eAnnotation( eAnnot ), m_pAction( NULL ), m_pFileSpec( NULL )
{
    PdfVariant    rect;
    PdfDate       date;
    PdfString     sDate;
    const PdfName name( TypeNameForIndex( eAnnot, s_names, s_lNumActions ) );

    if( !name.GetLength() )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    rRect.ToVariant( rect );

    m_pVariant->GetDictionary().AddKey( PdfName::KeyRect, rect );

    rRect.ToVariant( rect );
    date.ToString( sDate );
    
    m_pVariant->GetDictionary().AddKey( PdfName::KeySubtype, name );
    m_pVariant->GetDictionary().AddKey( PdfName::KeyRect, rect );
    m_pVariant->GetDictionary().AddKey( "P", pPage->GetObject()->Reference() );
    m_pVariant->GetDictionary().AddKey( "M", sDate );
}

PdfAnnotation::PdfAnnotation( PdfObject* pObject )
    : PdfElement( "Annot", pObject ), m_eAnnotation( ePdfAnnotation_Unknown ), m_pAction( NULL ), m_pFileSpec( NULL )
{
    m_eAnnotation = static_cast<EPdfAnnotation>(TypeNameToIndex( m_pVariant->GetDictionary().GetKeyAsName( PdfName::KeySubtype ).GetName().c_str(), s_names, s_lNumActions ));
}

PdfAnnotation::~PdfAnnotation()
{
    delete m_pAction;
    delete m_pFileSpec;
}

PdfRect PdfAnnotation::GetRect() const
{
   if( m_pVariant->GetDictionary().HasKey( PdfName::KeyRect ) )
        return PdfRect( m_pVariant->GetDictionary().GetKey( PdfName::KeyRect )->GetArray() );

   return PdfRect();
}

void PdfAnnotation::SetAppearanceStream( PdfXObject* pObject )
{
    PdfDictionary dict;

    if( !pObject )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    dict.AddKey( "N", pObject->GetObject()->Reference() );

    m_pVariant->GetDictionary().AddKey( "AP", dict );
}

void PdfAnnotation::SetFlags( pdf_uint32 uiFlags )
{
    m_pVariant->GetDictionary().AddKey( "F", PdfVariant( static_cast<long>(uiFlags) ) );
}

pdf_uint32 PdfAnnotation::GetFlags() const
{
    if( m_pVariant->GetDictionary().HasKey( "F" ) )
        return static_cast<pdf_uint32>(m_pVariant->GetDictionary().GetKey( "F" )->GetNumber());

    return static_cast<pdf_uint32>(0);
}

void PdfAnnotation::SetBorderStyle( double dHCorner, double dVCorner, double dWidth )
{
    this->SetBorderStyle( dHCorner, dVCorner, dWidth, PdfArray() );
}

void PdfAnnotation::SetBorderStyle( double dHCorner, double dVCorner, double dWidth, const PdfArray & rStrokeStyle )
{
    // TODO : Support for Border style for PDF Vers > 1.0
    PdfArray aValues;

    aValues.push_back(dHCorner);
    aValues.push_back(dVCorner);
    aValues.push_back(dWidth);
    if( rStrokeStyle.size() )
        aValues.push_back(rStrokeStyle);

    m_pVariant->GetDictionary().AddKey( "Border", aValues );
}

void PdfAnnotation::SetTitle( const PdfString & sTitle )
{
    m_pVariant->GetDictionary().AddKey( "T", sTitle );
}

PdfString PdfAnnotation::GetTitle() const
{
    if( m_pVariant->GetDictionary().HasKey( "T" ) )
        return m_pVariant->GetDictionary().GetKey( "T" )->GetString();

    return PdfString();
}

void PdfAnnotation::SetContents( const PdfString & sContents )
{
    m_pVariant->GetDictionary().AddKey( "Contents", sContents );
}

PdfString PdfAnnotation::GetContents() const
{
    if( m_pVariant->GetDictionary().HasKey( "Contents" ) )
        return m_pVariant->GetDictionary().GetKey( "Contents" )->GetString();

    return PdfString();
}

void PdfAnnotation::SetDestination( const PdfDestination & rDestination )
{
    rDestination.AddToDictionary( m_pVariant->GetDictionary() );
}

PdfDestination PdfAnnotation::GetDestination() const
{
    return PdfDestination( m_pVariant->GetDictionary().GetKey( "Dest" ) );
}

bool PdfAnnotation::HasDestination() const
{
    return m_pVariant->GetDictionary().HasKey( "Dest" );
}

void PdfAnnotation::SetAction( const PdfAction & rAction )
{
    if( m_pAction )
        delete m_pAction;

    m_pAction = new PdfAction( rAction );
    // XXX FIXME TODO: we can not safely assume actions are indirect objects. We must
    // be able to handle including them literally, or as a reference. Currently
    // we INCORRECTLY assume they're always indirect. We never could assume this, we'd just insert
    // an invalid reference (-1,-1) here before.
    m_pVariant->GetDictionary().AddKey( "A", static_cast<PdfObject*>(m_pAction->GetObject())->Reference() );
}

PdfAction* PdfAnnotation::GetAction() const
{
    if( !m_pAction && HasAction() )
    {
        const_cast<PdfAnnotation*>(this)->m_pAction = new PdfAction( m_pVariant->GetDictionary().GetKey( "A" ) );
    }

    return m_pAction;
}

bool PdfAnnotation::HasAction() const
{
    return m_pVariant->GetDictionary().HasKey( "A" );
}

void PdfAnnotation::SetOpen( bool b )
{
    m_pVariant->GetDictionary().AddKey( "Open", b );
}

bool PdfAnnotation::GetOpen() const
{
    if( m_pVariant->GetDictionary().HasKey( "Open" ) )
        return m_pVariant->GetDictionary().GetKey( "Open" )->GetBool();

    return false;
}

bool PdfAnnotation::HasFileAttachement() const
{
    return m_pVariant->GetDictionary().HasKey( "FS" );
}

void PdfAnnotation::SetFileAttachement( const PdfFileSpec & rFileSpec )
{
    if( m_pFileSpec )
        delete m_pFileSpec;

    m_pFileSpec = new PdfFileSpec( rFileSpec );
    // XXX FIXME TODO We incorrectly assume that FileSpec objects contain an indirect object.
    // That assumption is unsafe, but was made before. It needs to be fixed.
    m_pVariant->GetDictionary().AddKey( "FS", static_cast<PdfObject*>(m_pFileSpec->GetObject())->Reference() );
}

PdfFileSpec* PdfAnnotation::GetFileAttachement() const
{
    if( !m_pFileSpec && HasFileAttachement() )
        const_cast<PdfAnnotation*>(this)->m_pFileSpec = new PdfFileSpec( m_pVariant->GetDictionary().GetKey( "FS" ) );

    return m_pFileSpec;
}

};
