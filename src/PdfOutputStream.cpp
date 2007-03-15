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

#include "PdfOutputStream.h"

#include "PdfOutputDevice.h"

namespace PoDoFo {

PdfFileOutputStream::PdfFileOutputStream( const char* pszFilename )
{
    m_hFile = fopen( pszFilename, "wb" );
    if( !m_hFile ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_FileNotFound );
    }
}

long PdfFileOutputStream::Write( const char* pBuffer, long lLen )
{
    return fwrite( pBuffer, sizeof(char), lLen, m_hFile );
}

void PdfFileOutputStream::Close() 
{
    if( m_hFile ) 
        fclose( m_hFile );
}

PdfMemoryOutputStream::PdfMemoryOutputStream( long lInitial )
    : m_lLen( 0 )
{
    m_lSize   = lInitial;
    m_pBuffer = static_cast<char*>(malloc( m_lSize * sizeof(char) ));
    
    if( !m_pBuffer ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_OutOfMemory );
    }
}

PdfMemoryOutputStream::~PdfMemoryOutputStream()
{
    free( m_pBuffer );
}

long PdfMemoryOutputStream::Write( const char* pBuffer, long lLen )
{
    if( !m_pBuffer ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    if( m_lLen + lLen > m_lSize ) 
    {
        // a reallocation is required
        m_lSize = PDF_MAX( (m_lLen + lLen), (m_lSize << 1 ) );
        m_pBuffer = static_cast<char*>(realloc( m_pBuffer, m_lSize ));
        if( !m_pBuffer ) 
        {
            PODOFO_RAISE_ERROR( ePdfError_OutOfMemory );
        }
    }

    memcpy( m_pBuffer + m_lLen, pBuffer, lLen );
    m_lLen += lLen;
    
    return lLen;
}

PdfDeviceOutputStream::PdfDeviceOutputStream( PdfOutputDevice* pDevice )
    : m_pDevice( pDevice )
{
}

long PdfDeviceOutputStream::Write( const char* pBuffer, long lLen )
{
    long lTell = m_pDevice->GetLength();
    m_pDevice->Write( pBuffer, lLen );
    return m_pDevice->GetLength() - lTell;
}

};
