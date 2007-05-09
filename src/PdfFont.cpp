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

#include "PdfFont.h"

#include "PdfArray.h"
#include "PdfFontMetrics.h"
#include "PdfInputStream.h"
#include "PdfPage.h"
#include "PdfStream.h"
#include "PdfWriter.h"
#include "PdfLocale.h"

#include <sstream>

#define FIRST_CHAR   0
#define LAST_CHAR  255

using namespace std;

namespace PoDoFo {

PdfFont::PdfFont( PdfFontMetrics* pMetrics, bool bEmbedd, PdfVecObjects* pParent )
    : PdfIElement( "Font", pParent ), m_pMetrics( pMetrics )
{
    ostringstream out;
    PdfLocaleImbue(out);

    m_fFontSize   = 12.0;

    m_bBold       = false;
    m_bItalic     = false;
    m_bUnderlined = false;

    // Implementation note: the identifier is always
    // Prefix+ObjectNo. Prefix is /Ft for fonts.
    out << "Ft" << GetObject()->Reference().ObjectNumber();
    m_Identifier = PdfName( out.str().c_str() );

    this->Init( bEmbedd );
}
    
PdfFont::~PdfFont()
{
    delete m_pMetrics;
}

void PdfFont::Init( bool bEmbedd )
{
    unsigned int  i;
    int           curPos = 0;
    PdfObject*    pWidth;
    PdfObject*    pDescriptor;
    PdfVariant    var;
    PdfArray      array;
    std::string   sTmp;

    // replace all spaces in the base font name as suggested in 
    // the PDF reference section 5.5.2
    sTmp = m_pMetrics->GetFontname();
    for(i = 0; i < sTmp.size(); i++)
    {
        if(sTmp[i] != ' ')
            sTmp[curPos++] = sTmp[i];
    }
    sTmp.resize(curPos);
    m_BaseFont = PdfName( sTmp.c_str() );


    pWidth = GetObject()->GetOwner()->CreateObject();
    if( !pWidth )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    m_pMetrics->GetWidthArray( *pWidth, FIRST_CHAR, LAST_CHAR );

    pDescriptor = GetObject()->GetOwner()->CreateObject( "FontDescriptor" );
    if( !pDescriptor )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    GetObject()->GetDictionary().AddKey( PdfName::KeySubtype, PdfName("TrueType") );
    GetObject()->GetDictionary().AddKey("BaseFont", m_BaseFont );
    GetObject()->GetDictionary().AddKey("FirstChar", PdfVariant( static_cast<long>(FIRST_CHAR) ) );
    GetObject()->GetDictionary().AddKey("LastChar", PdfVariant( static_cast<long>(LAST_CHAR) ) );
    GetObject()->GetDictionary().AddKey("Encoding", PdfName("WinAnsiEncoding") );
    GetObject()->GetDictionary().AddKey("Widths", pWidth->Reference() );
    GetObject()->GetDictionary().AddKey( "FontDescriptor", pDescriptor->Reference() );

    m_pMetrics->GetBoundingBox( array );

    pDescriptor->GetDictionary().AddKey( "FontName", m_BaseFont );
    //pDescriptor->GetDictionary().AddKey( "FontWeight", (long)m_pMetrics->Weight() );
    pDescriptor->GetDictionary().AddKey( PdfName::KeyFlags, PdfVariant( 32l ) ); // TODO: 0 ????
    pDescriptor->GetDictionary().AddKey( "FontBBox", array );
    pDescriptor->GetDictionary().AddKey( "ItalicAngle", PdfVariant( static_cast<long>(m_pMetrics->GetItalicAngle()) ) );
    pDescriptor->GetDictionary().AddKey( "Ascent", m_pMetrics->GetPdfAscent() );
    pDescriptor->GetDictionary().AddKey( "Descent", m_pMetrics->GetPdfDescent() );
    pDescriptor->GetDictionary().AddKey( "CapHeight", m_pMetrics->GetPdfAscent() ); // //m_pMetrics->CapHeight() );
    pDescriptor->GetDictionary().AddKey( "StemV", PdfVariant( 1l ) ); //m_pMetrics->StemV() );

    if( bEmbedd )
    {
        EmbeddFont( pDescriptor );
    }
}

void PdfFont::EmbeddFont( PdfObject* pDescriptor )
{
    PdfObject* pContents;
    long       lSize = 0;

    pContents = GetObject()->GetOwner()->CreateObject();
    if( !pContents )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    pDescriptor->GetDictionary().AddKey( "FontFile2", pContents->Reference() );

    // if the data was loaded from memory - use it from there
    // otherwise, load from disk
    if ( m_pMetrics->GetFontDataLen() && m_pMetrics->GetFontData() ) 
    {
        // FIXME const_cast<char*> is dangerous if string literals may ever be passed
        char* pBuffer = const_cast<char*>( m_pMetrics->GetFontData() );
        lSize = m_pMetrics->GetFontDataLen();

        pContents->GetStream()->Set( pBuffer, lSize );
    } 
    else 
    {
        PdfFileInputStream stream( m_pMetrics->GetFilename() );
        pContents->GetStream()->Set( &stream );

        lSize = stream.GetFileLength();
    }
    
    pContents->GetDictionary().AddKey( "Length1", PdfVariant( lSize ) );
}

void PdfFont::SetFontSize( float fSize )
{
    m_pMetrics->SetFontSize( fSize );

    m_fFontSize = fSize;
}


};

