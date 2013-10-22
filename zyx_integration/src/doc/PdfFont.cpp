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

#include "base/PdfDefinesPrivate.h"

#include "base/PdfArray.h"
#include "base/PdfEncoding.h"
#include "base/PdfInputStream.h"
#include "base/PdfStream.h"
#include "base/PdfWriter.h"
#include "base/PdfLocale.h"

#include "PdfFontMetrics.h"
#include "PdfPage.h"

#include <stdlib.h>
#include <string.h>
#include <sstream>

using namespace std;

namespace PoDoFo {

PdfFont::PdfFont( PdfFontMetrics* pMetrics, const PdfEncoding* const pEncoding, PdfVecObjects* pParent )
    : PdfElement( "Font", pParent ), m_pEncoding( pEncoding ), 
      m_pMetrics( pMetrics ), m_bBold( false ), m_bItalic( false ), m_isBase14( false ), m_bIsSubsetting( false )

{
    this->InitVars();
}

PdfFont::PdfFont( PdfFontMetrics* pMetrics, const PdfEncoding* const pEncoding, PdfObject* pObject )
    : PdfElement( "Font", pObject ),
      m_pEncoding( pEncoding ), m_pMetrics( pMetrics ),
      m_bBold( false ), m_bItalic( false ), m_isBase14( false ), m_bIsSubsetting( false )

{
    // Implementation note: the identifier is always
    // Prefix+ObjectNo. Prefix is /Ft for fonts.
    ostringstream out;
    PdfLocaleImbue(out);
    out << "PoDoFoFt" << this->GetObject()->Reference().ObjectNumber();
    m_Identifier = PdfName( out.str().c_str() );
}

PdfFont::~PdfFont()
{
    if (m_pMetrics)
        delete m_pMetrics;
    if( m_pEncoding && m_pEncoding->IsAutoDelete() )
        delete m_pEncoding;
}

void PdfFont::InitVars()
{
    ostringstream out;
    PdfLocaleImbue(out);

    m_pMetrics->SetFontSize( 12.0 );
    m_pMetrics->SetFontScale( 100.0 );
    m_pMetrics->SetFontCharSpace( 0.0 );

    // Peter Petrov 24 Spetember 2008
    m_bWasEmbedded = false;

    m_bUnderlined = false;
    m_bStrikedOut = false;

    // Implementation note: the identifier is always
    // Prefix+ObjectNo. Prefix is /Ft for fonts.
    out << "Ft" << this->GetObject()->Reference().ObjectNumber();
    m_Identifier = PdfName( out.str().c_str() );

	

    // replace all spaces in the base font name as suggested in 
    // the PDF reference section 5.5.2#
    int curPos = 0;
    std::string sTmp = m_pMetrics->GetFontname();
    const char* pszPrefix = m_pMetrics->GetSubsetFontnamePrefix();
    if( pszPrefix ) 
    {
	std::string sPrefix = pszPrefix;
	sTmp = sPrefix + sTmp;
    }

    for(unsigned int i = 0; i < sTmp.size(); i++)
    {
        if(sTmp[i] != ' ')
            sTmp[curPos++] = sTmp[i];
    }
    sTmp.resize(curPos);
    m_BaseFont = PdfName( sTmp.c_str() );
}

inline char ToHex( const char byte )
{
    static const char* s_pszHex = "0123456789ABCDEF";

    return s_pszHex[byte % 16];
}

void PdfFont::WriteStringToStream( const PdfString & rsString, PdfStream* pStream )
{
    if( !m_pEncoding )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    PdfRefCountedBuffer buffer = m_pEncoding->ConvertToEncoding( rsString, this );
    pdf_long  lLen    = 0;
    char* pBuffer = NULL;

    std::auto_ptr<PdfFilter> pFilter = PdfFilterFactory::Create( ePdfFilter_ASCIIHexDecode );    
    pFilter->Encode( buffer.GetBuffer(), buffer.GetSize(), &pBuffer, &lLen );

    pStream->Append( "<", 1 );
    pStream->Append( pBuffer, lLen );
    pStream->Append( ">", 1 );

    free( pBuffer );
}

// Peter Petrov 5 January 2009
void PdfFont::EmbedFont()
{
    if (!m_bWasEmbedded)
    {
        // Now we embed the font

        // Now we set the flag
        m_bWasEmbedded = true;
    }
}

void PdfFont::EmbedSubsetFont()
{
	//virtual function is only implemented in derived class
    PODOFO_RAISE_ERROR_INFO( ePdfError_NotImplemented, "Subsetting not implemented for this font type." );
}

void PdfFont::AddUsedSubsettingGlyphs( const PdfString & , long )
{
	//virtual function is only implemented in derived class
    PODOFO_RAISE_ERROR_INFO( ePdfError_NotImplemented, "Subsetting not implemented for this font type." );
}

void PdfFont::AddUsedGlyphname( const char * )
{
	//virtual function is only implemented in derived class
    PODOFO_RAISE_ERROR_INFO( ePdfError_NotImplemented, "Subsetting not implemented for this font type." );
}

void PdfFont::SetBold( bool bBold )
{
    m_bBold = bBold;
}

void PdfFont::SetItalic( bool bItalic )
{
    m_bItalic = bItalic;
}

const PdfName& PdfFont::GetBaseFont() const
{
    return m_BaseFont;
}

const PdfName & PdfFont::GetIdentifier() const
{
    return m_Identifier;
}

void PdfFont::SetFontSize( float fSize )
{
    m_pMetrics->SetFontSize( fSize );
}

float PdfFont::GetFontSize() const
{
    return m_pMetrics->GetFontSize();
}

void PdfFont::SetFontScale( float fScale )
{
    m_pMetrics->SetFontScale( fScale );
}

float PdfFont::GetFontScale() const
{
    return  m_pMetrics->GetFontScale();
}

void PdfFont::SetFontCharSpace( float fCharSpace )
{
    m_pMetrics->SetFontCharSpace( fCharSpace );
}

float PdfFont::GetFontCharSpace() const
{
    return m_pMetrics->GetFontCharSpace();
}

void PdfFont::SetWordSpace( float fWordSpace )
{
    m_pMetrics->SetWordSpace( fWordSpace );
}

float PdfFont::GetWordSpace() const
{
    return m_pMetrics->GetWordSpace();
}

const PdfEncoding* PdfFont::GetEncoding() const
{
    return m_pEncoding;
}

PdfFontMetrics* PdfFont::GetFontMetrics2()
{
    return m_pMetrics;
}

const PdfFontMetrics* PdfFont::GetFontMetrics() const
{
    return m_pMetrics;
}

void PdfFont::SetUnderlined( bool bUnder )
{
    m_bUnderlined = bUnder;
}

bool PdfFont::IsUnderlined() const
{
    return m_bUnderlined;
}

void PdfFont::SetStrikeOut( bool bStrikeOut )
{
    m_bStrikedOut = bStrikeOut;
}

bool PdfFont::IsStrikeOut() const
{
    return m_bStrikedOut;
}

bool PdfFont::IsBold() const
{
    return m_bBold;
}

bool PdfFont::IsItalic() const
{
    return m_bItalic;
}

bool PdfFont::IsSubsetting() const
{
    return m_bIsSubsetting;
}

};
