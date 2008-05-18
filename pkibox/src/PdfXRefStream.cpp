/***************************************************************************
 *   Copyright (C) 2007 by Dominik Seichter                                *
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

#include "PdfXRefStream.h"

#include "PdfObject.h"
#include "PdfStream.h"
#include "PdfWriter.h"

// for htonl
#ifdef _WIN32
#include <winsock2.h>
#undef GetObject
#else 
#include <arpa/inet.h>
#endif // _WIN32

// alloca() is defined only in <cstdlib> on Mac OS X,
// only in <malloc.h> on win32, and in both on Linux.
#if defined(_WIN32)
#include <malloc.h>
#else
#include <cstdlib>
#endif

namespace PoDoFo {

#ifdef WIN32
typedef signed char 	int8_t;
typedef unsigned char 	uint8_t;
typedef signed short 	int16_t;
typedef unsigned short 	uint16_t;
typedef signed int 	int32_t;
typedef unsigned int 	uint32_t;
#endif

#define STREAM_OFFSET_TYPE uint32_t

bool podofo_is_little_endian()
{ 
    int _p = 1;
    return ((reinterpret_cast<char*>(&_p))[0] == 1);
}

PdfXRefStream::PdfXRefStream( PdfVecObjects* pParent, PdfWriter* pWriter )
    : m_pParent( pParent ), m_pWriter( pWriter ), m_pObject( NULL )
{
    m_bLittle    = podofo_is_little_endian();
    m_lBufferLen = 2 + sizeof( STREAM_OFFSET_TYPE );

    m_pObject    = pParent->CreateObject( "XRef" );
    m_lOffset    = 0;
}

PdfXRefStream::~PdfXRefStream()
{
}

void PdfXRefStream::BeginWrite( PdfOutputDevice* ) 
{
    m_pObject->GetStream()->BeginAppend();
}

void PdfXRefStream::WriteSubSection( PdfOutputDevice*, unsigned int nFirst, unsigned int nCount )
{
    PdfError::DebugMessage("Writing XRef section: %u %u\n", nFirst, nCount );

    m_indeces.push_back( static_cast<long>(nFirst) );
    m_indeces.push_back( static_cast<long>(nCount) );
}

void PdfXRefStream::WriteXRefEntry( PdfOutputDevice*, unsigned long lOffset, unsigned long lGeneration, 
                                    char cMode, unsigned long lObjectNumber ) 
{
    char *              buffer = reinterpret_cast<char*>(alloca(m_lBufferLen));
    STREAM_OFFSET_TYPE* pValue = reinterpret_cast<STREAM_OFFSET_TYPE*>(buffer+1);

    if( cMode == 'n' && lObjectNumber == m_pObject->Reference().ObjectNumber() )
        m_lOffset = lOffset;
    
    buffer[0]              = static_cast<char>( cMode == 'n' ? 1 : 0 );
    buffer[m_lBufferLen-1] = static_cast<char>( cMode == 'n' ? 0 : lGeneration );
    // TODO: This might cause bus errors on HP-UX machines 
    //       which require integers to be alligned on byte boundaries.
    //       -> Better use memcpy here!
    *pValue             = static_cast<STREAM_OFFSET_TYPE>(lOffset);
    if( m_bLittle )
        *pValue = static_cast<STREAM_OFFSET_TYPE>(htonl( *pValue ));
    
    m_pObject->GetStream()->Append( buffer, m_lBufferLen );
}

void PdfXRefStream::EndWrite( PdfOutputDevice* pDevice ) 
{
    PdfArray w;

    w.push_back( 1L );
    w.push_back( static_cast<long>(sizeof(STREAM_OFFSET_TYPE)) );
    w.push_back( 1L );

    // Add our self to the XRef table
    this->WriteXRefEntry( pDevice, pDevice->Tell(), 0, 'n' );

    m_pObject->GetStream()->EndAppend();
    m_pWriter->FillTrailerObject( m_pObject, this->GetSize(), false, false );

    m_pObject->GetDictionary().AddKey( "Index", m_indeces );
    m_pObject->GetDictionary().AddKey( "W", w );

    pDevice->Seek( m_lOffset );
    m_pObject->WriteObject( pDevice, NULL ); // DominikS: Requires encryption info??
    m_indeces.clear();
}

};

