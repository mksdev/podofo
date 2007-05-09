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

    GetObject()->GetDictionary().AddKey( PdfName::KeyRect, rect );

    rRect.ToVariant( rect );
    date.ToString( sDate );
    
    GetObject()->GetDictionary().AddKey( PdfName::KeySubtype, name );
    GetObject()->GetDictionary().AddKey( PdfName::KeyRect, rect );
    GetObject()->GetDictionary().AddKey( "P", pPage->GetObject()->Reference() );
    GetObject()->GetDictionary().AddKey( "M", sDate );
}

PdfAnnotation::PdfAnnotation( PdfVariant* pObject )
    : PdfElement( "Annot", pObject ), m_eAnnotation( ePdfAnnotation_Unknown ), m_pAction( NULL ), m_pFileSpec( NULL )
{
    m_eAnnotation = static_cast<EPdfAnnotation>(TypeNameToIndex( GetObject()->GetDictionary().GetKeyAsName( PdfName::KeySubtype ).GetName().c_str(), s_names, s_lNumActions ));
}

PdfAnnotation::~PdfAnnotation()
{
    delete m_pAction;
    delete m_pFileSpec;
}

PdfRect PdfAnnotation::GetRect() const
{
   if( GetObject()->GetDictionary().HasKey( PdfName::KeyRect ) )
        return PdfRect( GetObject()->GetDictionary().GetKey( PdfName::KeyRect )->GetArray() );

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

    GetObject()->GetDictionary().AddKey( "AP", dict );
}

void PdfAnnotation::SetFlags( pdf_uint32 uiFlags )
{
    GetObject()->GetDictionary().AddKey( "F", PdfVariant( static_cast<long>(uiFlags) ) );
}

pdf_uint32 PdfAnnotation::GetFlags() const
{
    if( GetObject()->GetDictionary().HasKey( "F" ) )
        return static_cast<pdf_uint32>(GetObject()->GetDictionary().GetKey( "F" )->GetNumber());

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

    GetObject()->GetDictionary().AddKey( "Border", aValues );
}

void PdfAnnotation::SetTitle( const PdfString & sTitle )
{
    GetObject()->GetDictionary().AddKey( "T", sTitle );
}

PdfString PdfAnnotation::GetTitle() const
{
    if( GetObject()->GetDictionary().HasKey( "T" ) )
        return GetObject()->GetDictionary().GetKey( "T" )->GetString();

    return PdfString();
}

void PdfAnnotation::SetContents( const PdfString & sContents )
{
    GetObject()->GetDictionary().AddKey( "Contents", sContents );
}

PdfString PdfAnnotation::GetContents() const
{
    if( GetObject()->GetDictionary().HasKey( "Contents" ) )
        return GetObject()->GetDictionary().GetKey( "Contents" )->GetString();

    return PdfString();
}

void PdfAnnotation::SetDestination( const PdfDestination & rDestination )
{
    rDestination.AddToDictionary( GetObject()->GetDictionary() );
}

PdfDestination PdfAnnotation::GetDestination() const
{
    return PdfDestination( GetObject()->GetDictionary().GetKey( "Dest" ) );
}

bool PdfAnnotation::HasDestination() const
{
    return GetObject()->GetDictionary().HasKey( "Dest" );
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
    GetObject()->GetDictionary().AddKey( "A", static_cast<PdfObject*>(m_pAction->GetObject())->Reference() );
}

PdfAction* PdfAnnotation::GetAction() const
{
    if( !m_pAction && HasAction() )
    {
        // FIXME Lots of const_casting here is a bit dodgy - is there a cleaner way?
        const_cast<PdfAnnotation*>(this)->m_pAction = new PdfAction( const_cast<PdfVariant*>(GetObject())->GetDictionary().GetKey( "A" ) );
    }

    return m_pAction;
}

bool PdfAnnotation::HasAction() const
{
    return GetObject()->GetDictionary().HasKey( "A" );
}

void PdfAnnotation::SetOpen( bool b )
{
    GetObject()->GetDictionary().AddKey( "Open", b );
}

bool PdfAnnotation::GetOpen() const
{
    if( GetObject()->GetDictionary().HasKey( "Open" ) )
        return GetObject()->GetDictionary().GetKey( "Open" )->GetBool();

    return false;
}

bool PdfAnnotation::HasFileAttachement() const
{
    return GetObject()->GetDictionary().HasKey( "FS" );
}

void PdfAnnotation::SetFileAttachement( const PdfFileSpec & rFileSpec )
{
    if( m_pFileSpec )
        delete m_pFileSpec;

    m_pFileSpec = new PdfFileSpec( rFileSpec );
    // XXX FIXME TODO We incorrectly assume that FileSpec objects contain an indirect object.
    // That assumption is unsafe, but was made before. It needs to be fixed.
    GetObject()->GetDictionary().AddKey( "FS", static_cast<PdfObject*>(m_pFileSpec->GetObject())->Reference() );
}

PdfFileSpec* PdfAnnotation::GetFileAttachement() const
{
    if( !m_pFileSpec && HasFileAttachement() )
        // TODO Lots of const casting here - is there a better way?
        const_cast<PdfAnnotation*>(this)->m_pFileSpec = new PdfFileSpec( const_cast<PdfVariant*>(GetObject())->GetDictionary().GetKey( "FS" ) );

    return m_pFileSpec;
}

};
