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

#include "PdfElement.h"

#include "PdfDictionary.h"
#include "PdfVariant.h"
#include "PdfVecObjects.h"

namespace PoDoFo {

PdfElement::PdfElement( const char* pszType, PdfVecObjects* pParent )
{
    // Create a new indirect object to use
    m_pVariant = pParent->CreateObject( pszType );
}

PdfElement::PdfElement( const char* pszType, PdfVariant* pVariant )
    : m_pVariant(pVariant)
{
    // Manage an existing PdfVariant (which may be a direct or indirect object)
    if( !m_pVariant )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    if( !m_pVariant->IsDictionary() ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }

    if( pszType && m_pVariant->GetDictionary().GetKeyAsName( PdfName::KeyType ) != pszType ) 
    {
        PdfError::LogMessage( eLogSeverity_Debug, "Expected key %s but got key %s.", 
                              pszType, m_pVariant->GetDictionary().GetKeyAsName( PdfName::KeyType ).GetName().c_str() );

        PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
    }
}

PdfElement::~PdfElement()
{
}

const char* PdfElement::TypeNameForIndex( int i, const char** ppTypes, long lLen ) const
{
    return ( i >= lLen ? NULL : ppTypes[i] );
}

int PdfElement::TypeNameToIndex( const char* pszType, const char** ppTypes, long lLen ) const
{
    int i;

    if( !pszType )
        return --lLen;

    for( i=0; i<lLen; i++ )
        if( strcmp( pszType, ppTypes[i] ) == 0 )
            return i;

    return --lLen;
}

PdfIElement::~PdfIElement()
{
}

};
