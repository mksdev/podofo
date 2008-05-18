/***************************************************************************
 *   Copyright (C) 2005 by Dominik Seichter                                *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <PdfDefines.h>

#include <PdfStreamedDocument.h>
#include <PdfFont.h>
#include <PdfFontMetrics.h>
#include <PdfInfo.h>
#include <PdfPage.h>
#include <PdfPainterMM.h>

using namespace PoDoFo;

#ifdef _HAVE_CONFIG
#include <config.h>
#endif // _HAVE_CONFIG

#define BORDER_TOP   10000 * CONVERSION_CONSTANT
#define BORDER_LEFT  10000 * CONVERSION_CONSTANT
#define FONT_SIZE    12.0

void print_help()
{
  printf("Usage: podofotxt2pdf [inputfile] [outputfile]\n\n");
}

void draw( char* pszBuffer, PdfDocument* pDocument )
{
    PdfPage*        pPage;
    PdfPainter      painter;
    PdfFont*        pFont;
    PdfRect         size;

    double dX       = BORDER_LEFT;
    double dY       = BORDER_TOP;
    char*  pszStart = pszBuffer;

    size            = PdfPage::CreateStandardPageSize( ePdfPageSize_A4 );
    pFont = pDocument->CreateFont( "Arial" );
    pPage = pDocument->CreatePage( size );

    if( !pFont )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }
    pFont->SetFontSize( FONT_SIZE );
    
    painter.SetPage( pPage );
    painter.SetFont( pFont );

    while( *pszBuffer )
    {
        if( *pszBuffer == '\n' )
        {
            painter.DrawText( dX, dY, pszStart, pszBuffer-pszStart );
    
            pszStart = (++pszBuffer);            

            dY += pFont->GetFontMetrics()->GetLineSpacing();
            if( dY > (size.GetHeight() -  BORDER_TOP) )
            {
                pPage = pDocument->CreatePage( size );
                painter.SetPage( pPage );
                dY       = BORDER_TOP;
            }
        }
        else
            ++pszBuffer;
    }

    painter.FinishPage();
}

void init( const char* pszInput, const char* pszOutput )
{
    FILE*   hFile;

    PdfStreamedDocument doc( pszOutput );

    char*  pszBuf;
    size_t lSize;

    hFile = fopen( pszInput, "rb" );	// read it as binary if we are going to compare sizes!
    if( !hFile )
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    fseek( hFile, 0x00, SEEK_END );
    lSize  = ftell( hFile );

    pszBuf = static_cast<char*>(malloc( sizeof( char ) * (lSize+1) ));
    fseek( hFile, 0x00, SEEK_SET );
    if( !pszBuf )
    {
        PODOFO_RAISE_ERROR( ePdfError_OutOfMemory );
    }

    // read the whole file into memory at once.
    // this not very efficient, but as this is 
    // a library demonstration I do not care.
    // If anyone wants to improve this: Go for it!
    if( fread( pszBuf, sizeof(char), lSize, hFile ) != lSize )
    {
        free( pszBuf );
        PODOFO_RAISE_ERROR( ePdfError_UnexpectedEOF );
    }

    fclose( hFile );

    pszBuf[lSize] = '\0';

    draw( pszBuf, &doc );

    doc.GetInfo()->SetCreator( PdfString("podofotxt2pdf") );
    doc.GetInfo()->SetTitle( PdfString("Converted to PDF from a text file") );
    doc.Close();

    free( pszBuf );
}

int main( int argc, char* argv[] )
{
  char*   pszInput;
  char*   pszOutput;

  if( argc != 3 )
  {
    print_help();
    exit( -1 );
  }

  pszInput  = argv[1];
  pszOutput = argv[2];

  try {
      init( pszInput, pszOutput );
  } catch( PdfError & e ) {
      fprintf( stderr, "Error %i occurred!\n", e.GetError() );
      e.PrintErrorMsg();
      return e.GetError();
  }

  return 0;
}

