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

#ifdef _MSC_VER
#pragma warning(disable: 4786)
#endif

#include <algorithm>
#include <deque>
#include <iostream>

#include "PdfArray.h"
#include "PdfDestination.h"
#include "PdfDictionary.h"
#include "PdfDocument.h"
#include "PdfFileSpec.h"
#include "PdfFont.h"
#include "PdfFontMetrics.h"
#include "PdfImmediateWriter.h"
#include "PdfInfo.h"
#include "PdfNamesTree.h"
#include "PdfObject.h"
#include "PdfOutlines.h"
#include "PdfPage.h"
#include "PdfPagesTree.h"
#include "PdfStream.h"
#include "PdfVecObjects.h"

namespace PoDoFo {

using namespace std;

PdfDocument::PdfDocument()
    : m_pOutlines( NULL ), m_pNamesTree( NULL ), m_pPagesTree( NULL ), 
      m_pTrailer( NULL ), m_fontCache( &m_vecObjects )
{
    m_eVersion    = ePdfVersion_1_3;
    m_bLinearized = false;
    m_vecObjects.SetParentDocument( this );

    m_pTrailer = new PdfVariant(PdfDictionary());
    m_pCatalog = m_vecObjects.CreateObject( "Catalog" );

    m_pInfo = new PdfInfo( &m_vecObjects );

    m_pTrailer->GetDictionary().AddKey( "Root", m_pCatalog->Reference() );
    m_pTrailer->GetDictionary().AddKey( "Info", m_pInfo->GetObject()->Reference() );

    InitPagesTree();
}

PdfDocument::PdfDocument( const char* pszFilename )
    : m_pInfo( NULL ), m_pOutlines( NULL ), m_pNamesTree( NULL ), m_pPagesTree( NULL ), 
      m_pTrailer( NULL ), m_fontCache( &m_vecObjects )
{
    m_vecObjects.SetParentDocument( this );

    this->Load( pszFilename );
}

PdfDocument::~PdfDocument()
{
    this->Clear();
}

void PdfDocument::Clear() 
{
    TIVecObjects     it     = m_vecObjects.begin();

    m_fontCache.EmptyCache();

    while( it != m_vecObjects.end() )
    {
        delete (*it);
        ++it;
    }

    m_vecObjects.Clear();

    if( m_pInfo ) 
    {
        delete m_pInfo;
        m_pInfo = NULL;
    }

    if( m_pNamesTree ) 
    {
        delete m_pNamesTree;
        m_pNamesTree = NULL;
    }

    if( m_pPagesTree ) 
    {
        delete m_pPagesTree;
        m_pPagesTree = NULL;
    }

    if( m_pOutlines ) 
    {
        delete m_pOutlines;
        m_pOutlines = NULL;
    }

    if ( m_pTrailer ) 
    {
        delete m_pTrailer;
        m_pTrailer = NULL;
    }
}

void PdfDocument::InitFromParser( PdfParser* pParser )
{
    PdfObject* pInfo;

    m_eVersion     = pParser->GetPdfVersion();
    m_bLinearized  = pParser->IsLinearized();

    m_pTrailer = new PdfVariant( *(pParser->GetTrailer()) );

    PdfVariant* pCatalogRef  = m_pTrailer->GetDictionary().GetKey( "Root" );
    // Catalog dictionary MUST be indirect reference in trailer
    if (!pCatalogRef || !pCatalogRef->IsReference())
    {
        PODOFO_RAISE_ERROR_INFO( ePdfError_NoObject, "/Root entry in trailer dictionary missing or not reference" );
    }

    m_pCatalog = m_vecObjects.GetObject(pCatalogRef->GetReference());
    if( !m_pCatalog )
    {
        PODOFO_RAISE_ERROR_INFO( ePdfError_NoObject, "Catalog object not found!" );
    }

    PdfVariant* pInfoRef = m_pTrailer->GetDictionary().GetKey( "Info" );
    if (pInfoRef && !pInfoRef->IsReference())
    {
        PODOFO_RAISE_ERROR_INFO( ePdfError_NoObject, "/Info entry in trailer dictionary must be indirect reference." );
    }
    else if (pInfoRef)
    {
        // Info entry specified and is indirect reference
        pInfo = m_vecObjects.GetObject(pInfoRef->GetReference());
    }
    else
    {
        // Info entry not specified in trailer dictionary
        pInfo = 0;
    }

    if( !pInfo )
    {
        m_pInfo = new PdfInfo( &m_vecObjects );
        m_pTrailer->GetDictionary().AddKey( "Info", m_pInfo->GetObject()->Reference() );
    }
    else 
        m_pInfo = new PdfInfo( pInfo );
}

void PdfDocument::InitPagesTree()
{
    PdfVariant* pagesRootRef = m_pCatalog->GetDictionary().GetKey( PdfName( "Pages" ) );
    // The pages key must be an indirect reference if it exists
    if (pagesRootRef && !pagesRootRef->IsReference())
    {
        PODOFO_RAISE_ERROR_INFO( ePdfError_InvalidDataType, "Pages entry in document catalog not indirect reference");
    }

    // If the pages key exists and points to a valid object, create a pages tree from it.
    // If it's missing, create a new page tree.
    PdfObject* pagesRootObj = 0;
    if (pagesRootRef)
    {
        pagesRootObj = m_vecObjects.GetObject(pagesRootRef->GetReference());
        if (!pagesRootObj)
        {
            PODOFO_RAISE_ERROR_INFO( ePdfError_NoObject, "Pages entry in document catalog refers to missing object");
        }
        m_pPagesTree = new PdfPagesTree( pagesRootObj );
    }
    else
    {
        m_pPagesTree = new PdfPagesTree( &m_vecObjects );
        m_pCatalog->GetDictionary().AddKey( "Pages", m_pPagesTree->GetObject()->Reference() );
    }
    assert(m_pPagesTree);
}

void PdfDocument::Load( const char* pszFilename )
{
    this->Clear();

    PdfParser parser( &m_vecObjects, pszFilename, true );
    InitFromParser( &parser );
    InitPagesTree();
}

void PdfDocument::Write( const char* pszFilename )
{
    /** TODO:
     *  We will get problems here on linux,
     *  if we write to the same filename we read the 
     *  document from.
     *  Because the PdfParserObjects will read there streams 
     *  data from the file while we are writing it.
     *  The problem is that the stream data won't exist at this time
     *  as we truncated the file already to zero length by opening
     *  it writeable.
     */
    PdfOutputDevice device( pszFilename );

    this->Write( &device );
}

void PdfDocument::Write( PdfOutputDevice* pDevice ) 
{
    /** TODO:
     *  We will get problems here on linux,
     *  if we write to the same filename we read the 
     *  document from.
     *  Because the PdfParserObjects will read there streams 
     *  data from the file while we are writing it.
     *  The problem is that the stream data won't exist at this time
     *  as we truncated the file already to zero length by opening
     *  it writeable.
     */
    PdfWriter       writer( this );

    writer.Write( pDevice );    
}

PdfVariant* PdfDocument::GetNamedObjectFromCatalog( const char* pszName ) const 
{
    return m_pCatalog->GetIndirectKey( PdfName( pszName ) );
}

PdfObject* PdfDocument::GetNamedIndirectObjectFromCatalog( const char* pszName ) const 
{
    // TODO ... verify safety and handling of error cases
    PdfVariant *const ref = m_pCatalog->GetDictionary().GetKey( PdfName( pszName ) );
    if (!ref)
        return NULL;
    // ref->GetReference() will throw appropriately if it's not actually a reference
    return m_vecObjects.GetObject(ref->GetReference());
}

int PdfDocument::GetPageCount() const
{
    return m_pPagesTree->GetTotalNumberOfPages();
}

PdfPage* PdfDocument::GetPage( int nIndex ) const
{
    if( nIndex < 0 || nIndex > m_pPagesTree->GetTotalNumberOfPages() )
    {
        PODOFO_RAISE_ERROR( ePdfError_ValueOutOfRange );
    }

    return m_pPagesTree->GetPage( nIndex );
}

PdfFont* PdfDocument::CreateFont( const char* pszFontName, bool bEmbedd )
{
    return m_fontCache.GetFont( pszFontName, bEmbedd );
}

PdfFont* PdfDocument::CreateFont( FT_Face face, bool bEmbedd )
{
    return m_fontCache.GetFont( face, bEmbedd );
}

PdfPage* PdfDocument::CreatePage( const PdfRect & rSize )
{
    return m_pPagesTree->CreatePage( rSize );
}

const PdfDocument & PdfDocument::Append( const PdfDocument & rDoc )
{
    int difference = m_vecObjects.GetSize() + m_vecObjects.GetFreeObjects().size();

    // append all objects first and fix their references
    TCIVecObjects it           = rDoc.GetObjects().begin();
    while( it != rDoc.GetObjects().end() )
    {
        PdfObject* pObj = new PdfObject( PdfReference( (*it)->Reference().ObjectNumber() + difference, 0 ), *(*it) );
        m_vecObjects.push_back( pObj );

        if( (*it)->IsDictionary() && (*it)->HasStream() )
            *(pObj->GetStream()) = *((*it)->GetStream());

        FixObjectReferences( pObj, difference );

        ++it;
    }

    // create all free objects again, to have a clean free object list
    TCIPdfReferenceList itFree = rDoc.GetObjects().GetFreeObjects().begin();
    while( itFree != rDoc.GetObjects().GetFreeObjects().end() )
    {
        m_vecObjects.AddFreeObject( PdfReference( (*itFree).ObjectNumber() + difference, 0 ) );

        ++itFree;
    }

    // append all pages now to our page tree
    for(int i=0;i<rDoc.GetPageCount();i++ )
    {
        PdfPage*      pPage = rDoc.GetPage( i );
        PdfObject*    pObj  = m_vecObjects.GetObject( PdfReference( pPage->GetObject()->Reference().ObjectNumber() + difference, 0 ) );
        if( pObj->IsDictionary() && pObj->GetDictionary().HasKey( "Parent" ) )
            pObj->GetDictionary().RemoveKey( "Parent" );

        m_pPagesTree->InsertPage( this->GetPageCount()-1, pObj );
    }

    // append all outlines
    PdfOutlineItem* pRoot       = this->GetOutlines();
    PdfOutlines*    pAppendRoot = const_cast<PdfDocument&>(rDoc).GetOutlines( PoDoFo::ePdfDontCreateObject );
    if( pAppendRoot && pAppendRoot->First() ) 
    {
        // only append outlines if appended document has outlines
        while( pRoot && pRoot->Next() ) 
            pRoot = pRoot->Next();

        printf("Reached last node difference=%i\n", difference);
        // XXX FIXME TODO The following code assumes that `pAppendRoot->First()->GetObject()' will be a PdfObject.
        printf("First: %li 0 R\n", pAppendRoot->First()->GetObject()->Reference().ObjectNumber() );
        PdfReference ref( pAppendRoot->First()->GetObject()->Reference().ObjectNumber() + difference, 0 );
        pRoot->InsertChild( new PdfOutlines( m_vecObjects.GetObject( ref ) ) );
    }

    // TODO: merge name trees
    // ToDictionary -> then iteratate over all keys and add them to the new one
    return *this;
}

void PdfDocument::FixObjectReferences( PdfVariant* pVariant, int difference )
{
    if( !pVariant ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    if( pVariant->IsReference() )
    {
        pVariant->GetReference().SetObjectNumber( pVariant->GetReference().ObjectNumber() + difference );
    }
    else if( pVariant->IsDictionary() )
    {
        TKeyMap::iterator it = pVariant->GetDictionary().GetKeys().begin();

        while( it != pVariant->GetDictionary().GetKeys().end() )
        {
            FixObjectReferences( (*it).second, difference );
            ++it;
        }
    }
    else if( pVariant->IsArray() )
    {
        PdfArray::iterator it = pVariant->GetArray().begin();

        while( it != pVariant->GetArray().end() )
        {
            FixObjectReferences( &(*it), difference );
            ++it;
        }
    }
}

void PdfDocument::DeletePages( int inFirstPage, int inNumPages )
{
    for( int i = 0 ; i < inNumPages ; i++ )
    {
        m_pPagesTree->DeletePage( inFirstPage ) ;
    }
}

const PdfDocument & PdfDocument::InsertPages( const PdfDocument & rDoc, int inFirstPage, int inNumPages )
{
    /*
      This function works a bit different than one might expect. 
      Rather than copying one page at a time - we copy the ENTIRE document
      and then delete the pages we aren't interested in.
      
      We do this because 
      1) SIGNIFICANTLY simplifies the process
      2) Guarantees that shared objects aren't copied multiple times
      3) offers MUCH faster performance for the common cases
      
      HOWEVER: because PoDoFo doesn't currently do any sort of "object garbage collection" during
      a Write() - we will end up with larger documents, since the data from unused pages
      will also be in there.
    */

    // calculate preliminary "left" and "right" page ranges to delete
    // then offset them based on where the pages were inserted
    // NOTE: some of this will change if/when we support insertion at locations
    //       OTHER than the end of the document!
    int leftStartPage = 0 ;
    int leftCount = inFirstPage ;
    int rightStartPage = inFirstPage + inNumPages ;
    int rightCount = rDoc.GetPageCount() - rightStartPage ;
    int pageOffset = this->GetPageCount();	

    leftStartPage += pageOffset ;
    rightStartPage += pageOffset ;
    
    // append in the whole document
    this->Append( rDoc );

    // delete
    if( rightCount > 0 )
        this->DeletePages( rightStartPage, rightCount ) ;
    if( leftCount > 0 )
        this->DeletePages( leftStartPage, leftCount ) ;
    
    return *this;
}

EPdfPageMode PdfDocument::GetPageMode( void ) const
{
    // PageMode is optional; the default value is UseNone
    EPdfPageMode thePageMode = ePdfPageModeUseNone;
    
    PdfVariant* pageModeObj = GetCatalog()->GetIndirectKey( PdfName( "PageMode" ) );
    if ( pageModeObj != NULL ) {
        PdfName pmName = pageModeObj->GetName();
        
        if( PdfName( "UseNone" ) == pmName )
            thePageMode = ePdfPageModeUseNone ;
        else if( PdfName( "UseThumbs" ) == pmName )
            thePageMode = ePdfPageModeUseThumbs ;
        else if( PdfName( "UseOutlines" ) == pmName )
            thePageMode = ePdfPageModeUseBookmarks ;
        else if( PdfName( "FullScreen" ) == pmName )
            thePageMode = ePdfPageModeFullScreen ;
        else if( PdfName( "UseOC" ) == pmName )
            thePageMode = ePdfPageModeUseOC ;
        else if( PdfName( "UseAttachments" ) == pmName )
            thePageMode = ePdfPageModeUseAttachments ;
        else
            PODOFO_RAISE_ERROR( ePdfError_InvalidName );
    }
    
    return thePageMode ;
}

void PdfDocument::SetPageMode( EPdfPageMode inMode ) const
{
    switch ( inMode ) {
        default:
        case ePdfPageModeUnknown:
        case ePdfPageModeDontCare:	
            // GetCatalog()->RemoveKey( PdfName( "PageMode" ) );
            // this value means leave it alone!
            break;
            
        case ePdfPageModeUseNone:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "UseNone" ) );
            break;
            
        case ePdfPageModeUseThumbs:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "UseThumbs" ) );
            break;
            
        case ePdfPageModeUseBookmarks:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "UseOutlines" ) );
            break;
            
        case ePdfPageModeFullScreen:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "FullScreen" ) );
            break;
            
        case ePdfPageModeUseOC:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "UseOC" ) );
            break;
            
        case ePdfPageModeUseAttachments:
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageMode" ), PdfName( "UseAttachments" ) );
            break;
    }
}

void PdfDocument::SetUseFullScreen( void ) const
{
    // first, we get the current mode
    EPdfPageMode	curMode = GetPageMode();
    
    // if current mode is anything but "don't care", we need to move that to non-full-screen
    if ( curMode != ePdfPageModeDontCare )
        SetViewerPreference( PdfName( "NonFullScreenPageMode" ), PdfVariant( *(GetCatalog()->GetIndirectKey( PdfName( "PageMode" ) )) ) );
    
    SetPageMode( ePdfPageModeFullScreen );
}

void PdfDocument::SetViewerPreference( const PdfName& whichPref, const PdfVariant & valueObj ) const
{
    PdfVariant* prefsObj = GetCatalog()->GetIndirectKey( PdfName( "ViewerPreferences" ) );
    if ( prefsObj == NULL ) {
        // make me a new one and add it
        PdfDictionary	vpDict;
        vpDict.AddKey( whichPref, valueObj );
        
        GetCatalog()->GetDictionary().AddKey( PdfName( "ViewerPreferences" ), PdfObject( vpDict ) );
    } else {
        // modify the existing one
        prefsObj->GetDictionary().AddKey( whichPref, valueObj );
    }
}

void PdfDocument::SetViewerPreference( const PdfName& whichPref, bool inValue ) const
{
    SetViewerPreference( whichPref, PdfObject( inValue ) );
}

void PdfDocument::SetHideToolbar( void )
{
    SetViewerPreference( PdfName( "HideToolbar" ), true );
}

void PdfDocument::SetHideMenubar( void )
{
    SetViewerPreference( PdfName( "HideMenubar" ), true );
}

void PdfDocument::SetHideWindowUI( void )
{
    SetViewerPreference( PdfName( "HideWindowUI" ), true );
}

void PdfDocument::SetFitWindow( void )
{
    SetViewerPreference( PdfName( "FitWindow" ), true );
}

void PdfDocument::SetCenterWindow( void )
{
    SetViewerPreference( PdfName( "CenterWindow" ), true );
}

void PdfDocument::SetDisplayDocTitle( void )
{
    SetViewerPreference( PdfName( "DisplayDocTitle" ), true );
}

void PdfDocument::SetPrintScaling( PdfName& inScalingType )
{
    SetViewerPreference( PdfName( "PrintScaling" ), inScalingType );
}

void PdfDocument::SetBaseURI( const std::string& inBaseURI )
{
    PdfDictionary	uriDict;
    uriDict.AddKey( PdfName( "Base" ), new PdfObject( PdfString( inBaseURI ) ) );
    GetCatalog()->GetDictionary().AddKey( PdfName( "URI" ), new PdfObject( uriDict ) );
}

void PdfDocument::SetLanguage( const std::string& inLanguage )
{
    GetCatalog()->GetDictionary().AddKey( PdfName( "Lang" ), new PdfObject( PdfString( inLanguage ) ) );
}

void PdfDocument::SetBindingDirection( PdfName& inDirection )
{
    SetViewerPreference( PdfName( "Direction" ), inDirection );
}

void PdfDocument::SetPageLayout( EPdfPageLayout inLayout )
{
    switch ( inLayout ) {
        default:
        case ePdfPageLayoutIgnore:
        case ePdfPageLayoutUnknown:
            break;	// means do nothing
        case ePdfPageLayoutDefault:			
            GetCatalog()->GetDictionary().RemoveKey( PdfName( "PageLayout" ) );
            break;
        case ePdfPageLayoutSinglePage:		
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "SinglePage" ) );
            break;
        case ePdfPageLayoutOneColumn:		
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "OneColumn" ) );
            break;
        case ePdfPageLayoutTwoColumnLeft:	
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "TwoColumnLeft" ) );
            break;
        case ePdfPageLayoutTwoColumnRight: 	
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "TwoColumnRight" ) );
            break;
        case ePdfPageLayoutTwoPageLeft: 	
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "TwoPageLeft" ) );
            break;
        case ePdfPageLayoutTwoPageRight: 	
            GetCatalog()->GetDictionary().AddKey( PdfName( "PageLayout" ), PdfName( "TwoPageRight" ) );
            break;
    }
}

PdfOutlines* PdfDocument::GetOutlines( bool bCreate )
{
    PdfObject* pObj;

    if( !m_pOutlines )
    {
        pObj = GetNamedIndirectObjectFromCatalog( "Outlines" );
        if( !pObj ) 
        {
            if ( !bCreate )	return NULL;
            
            m_pOutlines = new PdfOutlines( &m_vecObjects );
            m_pCatalog->GetDictionary().AddKey( "Outlines", m_pOutlines->GetObject()->Reference() );
        } else if ( pObj->GetDataType() != ePdfDataType_Dictionary ) {
            PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
        } else
            m_pOutlines = new PdfOutlines( pObj );
    }        
    
    return m_pOutlines;
}

PdfNamesTree* PdfDocument::GetNamesTree( bool bCreate )
{
    if( !m_pNamesTree )
    {
        // XXX FIXME TODO We unsafely assume that the names tree is an indirect object.
        PdfObject* namesTreeObj = static_cast<PdfObject*>(GetNamedObjectFromCatalog( "Names" ));
        if( !namesTreeObj ) 
        {
            if ( !bCreate )
                return NULL;

            // XXX FIXME TODO We unsafely assume that the names tree is an indirect object.
            // This does not appear to be required by the specification - see 3.6.1, "Names".
            // It'll work until PdfNamesTree gets fixed, though.
            PdfNamesTree tmpTree ( &m_vecObjects );
            PdfObject* pObj = tmpTree.GetObject();
            m_pCatalog->GetDictionary().AddKey( "Names", pObj->Reference() );
            m_pNamesTree = new PdfNamesTree( pObj, m_pCatalog );
        } else if ( namesTreeObj->GetDataType() != ePdfDataType_Dictionary ) {
            PODOFO_RAISE_ERROR( ePdfError_InvalidDataType );
        } else
            m_pNamesTree = new PdfNamesTree( namesTreeObj, m_pCatalog );
    }

    return m_pNamesTree;
}

void PdfDocument::AddNamedDestination( const PdfDestination& rDest, const PdfString & rName )
{
    PdfNamesTree* nameTree = GetNamesTree();
    nameTree->AddValue( PdfName("Dests"), rName, rDest.GetObject()->Reference() );
}

void PdfDocument::AttachFile( const PdfFileSpec & rFileSpec )
{
    PdfNamesTree* pNames = this->GetNamesTree( true );

    if( !pNames ) 
    {
        PODOFO_RAISE_ERROR( ePdfError_InvalidHandle );
    }

    // XXX FIXME TODO We unsafely assume that the filespec refers to an indirect object.
    // This need not be the case.
    pNames->AddValue( "EmbeddedFiles", rFileSpec.GetFilename(), static_cast<const PdfObject*>(rFileSpec.GetObject())->Reference() );
}

};

