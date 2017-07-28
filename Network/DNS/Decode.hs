{-# LANGUAGE OverloadedStrings, DeriveDataTypeable, CPP #-}

module Network.DNS.Decode (
    decode
  , decodeDomain
  , decodeDNSFlags
  , decodeDNSHeader
  , decodeResourceRecord
  , decodeMany
  , receive
  , receiveVC
  ) where

import Control.Applicative (many)
import Control.Monad (replicateM)
import Control.Monad.Trans.Resource (ResourceT, runResourceT)
import qualified Control.Exception as ControlException
import Data.Bits ((.&.), shiftR, testBit)
import Data.Char (ord)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
--import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Conduit (($$), ($$+), ($$+-), (=$), Source)
import Data.Conduit.Network (sourceSocket)
import qualified Data.Conduit.Binary as CB
import Data.IP (IP(..), toIPv4, toIPv6b)
import Data.Typeable (Typeable)
import Data.Word (Word16)
import Network (Socket)
import Network.DNS.Internal
import Network.DNS.StateBinary
import Numeric (showHex)
import qualified Safe

#if __GLASGOW_HASKELL__ < 709
import Control.Applicative
#endif

----------------------------------------------------------------


data RDATAParseError = RDATAParseError String
 deriving (Show, Typeable)

instance ControlException.Exception RDATAParseError


-- | Receiving DNS data from 'Socket' and parse it.

receive :: Socket -> IO DNSMessage
receive = receiveDNSFormat . sourceSocket

-- | Receive and parse a single virtual-circuit (TCP) response.  It
--   is up to the caller to implement any desired timeout.  This
--   (and the other response decoding functions) may throw ParseError
--   when the server response is incomplete or malformed.

receiveVC :: Socket -> IO DNSMessage
receiveVC sock = runResourceT $ do
    (src, lenbytes) <- sourceSocket sock $$+ CB.take 2
    let len = case map ord $ LBS.unpack lenbytes of
                [hi, lo] -> 256 * hi + lo
                _        -> 0
    fmap fst (src $$+- CB.isolate len =$ sinkSGet getResponse)

----------------------------------------------------------------

-- | Parsing DNS data.

decode :: ByteString -> Either String DNSMessage
decode bs = fst <$> runSGet getResponse bs

-- | Parse many length-encoded DNS records, for example, from TCP traffic.

decodeMany :: ByteString -> Either String ([DNSMessage], ByteString)
decodeMany bs = do
    ((bss, _), leftovers) <- runSGetWithLeftovers lengthEncoded bs
    msgs <- mapM decode bss
    return (msgs, leftovers)
  where
    -- Read a list of length-encoded lazy bytestrings
    lengthEncoded :: SGet [ByteString]
    lengthEncoded = many $ do
      len <- getInt16
      getNByteString len

decodeDNSFlags :: ByteString -> Either String DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs

decodeDNSHeader :: ByteString -> Either String DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

decodeDomain :: ByteString -> Either String Domain
decodeDomain bs = fst <$> runSGet getDomain bs

decodeResourceRecord :: ByteString -> Either String ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs

----------------------------------------------------------------
receiveDNSFormat :: Source (ResourceT IO) ByteString -> IO DNSMessage
receiveDNSFormat src = fst <$> runResourceT (src $$ sink)
  where
    sink = sinkSGet getResponse

----------------------------------------------------------------

getResponse :: SGet DNSMessage
getResponse = do
    hd <- getHeader
    qdCount <- getInt16
    anCount <- getInt16
    nsCount <- getInt16
    arCount <- getInt16
    DNSMessage hd <$> getQueries qdCount
                  <*> getResourceRecords anCount
                  <*> getResourceRecords nsCount
                  <*> getResourceRecords arCount

----------------------------------------------------------------

getDNSFlags :: SGet DNSFlags
getDNSFlags = do
    word <- get16
    maybe (fail $ "Unsupported flags: 0x" ++ showHex word "") pure (toFlags word)
  where
    toFlags :: Word16 -> Maybe DNSFlags
    toFlags flgs = do
        oc <- getOpcode flgs
        rc <- getRcode flgs
        return $ DNSFlags (getQorR flgs)
                          oc
                          (getAuthAnswer flgs)
                          (getTrunCation flgs)
                          (getRecDesired flgs)
                          (getRecAvailable flgs)
                          rc
                          (getAuthenData flgs)
      where
        getQorR w = if testBit w 15 then QR_Response else QR_Query
        getOpcode w = Safe.toEnumMay (fromIntegral (shiftR w 11 .&. 0x0f))
        getAuthAnswer w = testBit w 10
        getTrunCation w = testBit w 9
        getRecDesired w = testBit w 8
        getRecAvailable w = testBit w 7
        getRcode w = Safe.toEnumMay (fromIntegral (w .&. 0x0f))
        getAuthenData w = testBit w 5

----------------------------------------------------------------

getHeader' :: SGet (DNSHeader, (Int, Int, Int, Int))
getHeader' = do
    w <- getNByteString 12
    let decodeID = fromIntegral . getWord16BE $ w  -- 2 bytes
        flagsE = decodeDNSFlags . B.drop 2 $ w --2 bytes
        qdCount = fromIntegral . getWord16BE . B.drop 4 $ w -- 2 bytes
        anCount = fromIntegral . getWord16BE . B.drop 6 $ w -- 2 bytes
        nsCount = fromIntegral . getWord16BE . B.drop 8 $ w -- 2 bytes
        arCount = fromIntegral . getWord16BE . B.drop 10 $ w -- 2 bytes
        mkRes myFlags = return (DNSHeader decodeID myFlags, (qdCount, anCount, nsCount, arCount))
    either (fail . (mappend "bad dns flags: ")) mkRes flagsE

getHeader :: SGet DNSHeader
getHeader = fst <$> getHeader'

----------------------------------------------------------------

getQueries :: Int -> SGet [Question]
getQueries n = replicateM n getQuery

getQuery :: SGet Question
getQuery = go <$> getDomain <*> getNByteString 4 where
    go dd bs = Question dd (intToType . fromIntegral . getWord16BE $ bs)

getResourceRecords :: Int -> SGet [ResourceRecord]
getResourceRecords n = replicateM n getResourceRecord

getResourceRecord :: SGet ResourceRecord
getResourceRecord = do
    dom <- getDomain
    bs <- getNByteString 10
    let typ = intToType . fromIntegral . getWord16BE $ bs -- decodeType
        decodeBytes = B.drop 2 bs
    decodeRR' decodeBytes dom typ
  where
    decodeRR' bytes _ OPT = do
        let udps = fromIntegral . getWord16BE $ bytes -- 2 bytes
            -- _ = decodeERCode  -- 1 byte
            ver = fromIntegral . B.head . B.drop 3 $ bytes -- 1 byte
            dok =  flip testBit 15 . getWord16BE . B.drop 4 $ bytes -- 2 bytes
            len = fromIntegral . getWord16BE . B.drop 6 $ bytes -- 2 bytes
        dat <- getRData OPT len
        return $ OptRecord udps dok ver dat
    decodeRR' bytes dom t = do
        let -- _ = ignoreClass  -- 2 bytes
            ttl = fromIntegral . getWord32BE . B.drop 2 $ bytes -- 4 bytes
            len = fromIntegral . getWord16BE . B.drop 6 $ bytes -- 2 bytes
        dat <- getRData t len
        return $ ResourceRecord dom t ttl dat

getRData :: TYPE -> Int -> SGet RData
getRData NS _ = RD_NS <$> getDomain
getRData MX _ = RD_MX <$> decodePreference <*> getDomain
  where decodePreference = get16
getRData CNAME _ = RD_CNAME <$> getDomain
getRData DNAME _ = RD_DNAME <$> getDomain
getRData TXT len = (RD_TXT . ignoreLength) <$> getNByteString len
  where ignoreLength = BS.drop 1
getRData A len
  | len == 4  = (RD_A . toIPv4) <$> getNBytes len
  | otherwise = fail "IPv4 addresses must be 4 bytes long"
getRData AAAA len
  | len == 16 = (RD_AAAA . toIPv6b) <$> getNBytes len
  | otherwise = fail "IPv6 addresses must be 16 bytes long"
getRData SOA _ = go <$> getDomain <*> getDomain <*> getNByteString 20
  where
    go dd0 dd1 bs = RD_SOA dd0
                           dd1
                           decodeSerial
                           decodeRefesh
                           decodeRetry
                           decodeExpire
                           decodeMinumun
      where
        decodeSerial  = fromIntegral . getWord32BE $ bs
        decodeRefesh  = fromIntegral . getWord32BE . B.drop 4 $ bs
        decodeRetry   = fromIntegral . getWord32BE . B.drop 8 $ bs
        decodeExpire  = fromIntegral . getWord32BE . B.drop 12 $ bs
        decodeMinumun = fromIntegral . getWord32BE . B.drop 16 $ bs
getRData PTR _ = RD_PTR <$> getDomain
getRData SRV _ = go <$> getNByteString 6 <*> getDomain where
    go bs dd = RD_SRV decodePriority
                      decodeWeight
                      decodePort
                      dd
      where
        decodePriority = fromIntegral . getWord16BE $ bs
        decodeWeight   = fromIntegral . getWord16BE . B.drop 2 $ bs
        decodePort     = fromIntegral . getWord16BE . B.drop 4 $ bs
getRData OPT ol = RD_OPT <$> decode' ol
  where
    decode' :: Int -> SGet [OData]
    decode' l
        | l  < 0 = fail $ "decodeOPTData: length inconsistency (" ++ show l ++ ")"
        | l == 0 = pure []
        | otherwise = do
            bs <- getNByteString 4
            let optCode = intToOptType . fromIntegral . getWord16BE $ bs
                optLen = fromIntegral . getWord16BE . B.drop 2 $ bs
            dat <- getOData optCode optLen
            (dat:) <$> decode' (l - optLen - 4)
getRData TLSA len = go <$> getNByteString len where
    go bs = RD_TLSA decodeUsage
                    decodeSelector
                    decodeMType
                    decodeADF
      where
        decodeUsage    = B.head $ bs
        decodeSelector = B.head . B.drop 1 $ bs
        decodeMType    = B.head . B.drop 2 $ bs
        decodeADF      = B.drop 3 bs
getRData DS len = RD_DS <$> decodeTag
                           <*> decodeAlg
                           <*> decodeDtyp
                           <*> decodeDval
  where
    decodeTag  = get16
    decodeAlg  = get8
    decodeDtyp = get8
    decodeDval = getNByteString (len - 4)
getRData _  len = RD_OTH <$> getNByteString len

getOData :: OPTTYPE -> Int -> SGet OData
getOData ClientSubnet len = do
    bytes <- getNByteString (32 + len - 4)
    let fam = getWord16BE $ bytes --  getInt16
        srcMask = fromIntegral . B.head . B.drop 2 $ bytes -- getInt8
        scpMask = fromIntegral . B.head . B.drop 3 $ bytes -- getInt8
        rawip = fmap fromIntegral . B.unpack . B.drop 4 $ bytes -- <$> getNByteString (len - 4) -- 4 = 2 + 1 + 1
    ip <- case fam of
            1 -> pure . IPv4 . toIPv4 $ take 4 (rawip ++ repeat 0)
            2 -> pure . IPv6 . toIPv6b $ take 16 (rawip ++ repeat 0)
            _ -> fail "Unsupported address family"
    pure $ OD_ClientSubnet srcMask scpMask ip
getOData (OUNKNOWN i) len = OD_Unknown i <$> getNByteString len

----------------------------------------------------------------

getDomain :: SGet Domain
getDomain = do
    pos <- getPosition
    c <- getInt8
    let n = getValue c
    -- Syntax hack to avoid using MultiWayIf
    case () of
        _ | c == 0 -> return "." -- Perhaps the root domain?
        _ | isPointer c -> do
            d <- getInt8
            let offset = n * 256 + d
            mo <- pop offset
            case mo of
                Nothing -> fail $ "getDomain: " ++ show offset
                -- A pointer may refer to another pointer.
                -- So, register this position for the domain.
                Just o -> push pos o >> return o
        -- As for now, extended labels have no use.
        -- This may change some time in the future.
        _ | isExtLabel c -> return ""
        _ -> do
            hs <- getNByteString n
            ds <- getDomain
            let dom =
                    case ds of -- avoid trailing ".."
                        "." -> hs `BS.append` "."
                        _   -> hs `BS.append` "." `BS.append` ds
            push pos dom
            return dom
  where
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6

-- ignoreClass :: SGet ()
-- ignoreClass = () <$ get16
