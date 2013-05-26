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

#include "PdfData.h"

#include "PdfOutputDevice.h"
#include "PdfDefinesPrivate.h"

namespace PoDoFo {

PdfData::PdfData( const char* pszData )
	: PdfDataType(), m_sData( pszData ) 
{
}

PdfData::PdfData( const char* pszData, size_t dataSize )
  : PdfDataType(), m_sData( pszData, dataSize ) 
{
}

PdfData::PdfData( const PdfData & rhs )
  : PdfDataType()
{
   this->operator=( rhs );
}

void PdfData::Write( PdfOutputDevice* pDevice, EPdfWriteMode, const PdfEncrypt* ) const
{
    pDevice->Write( m_sData.c_str(), m_sData.length() );
}

const PdfData & PdfData::operator=( const PdfData & rhs )
{
    m_sData = rhs.m_sData;
    return (*this);
}

const std::string & PdfData::data() const {
    return m_sData;
}

};
