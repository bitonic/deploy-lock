{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import           Prelude                               hiding (catch)

import           Control.Applicative                   ((<|>))
import           Control.Concurrent.MVar               (MVar, newMVar, modifyMVar, readMVar)
import           Control.Exception                     (throwIO, catch)
import           Control.Monad                         (forM, mzero, when, forM_, join)
import           Control.Monad.IO.Class                (liftIO)
import           Control.Monad.Trans.Maybe             (MaybeT(MaybeT), runMaybeT)
import           Crypto.Random                         (genBytes, newGenIO)
import           Crypto.Random.DRBG                    (HashDRBG)
import qualified Data.ByteString                       as B
import qualified Data.ByteString.Base64.URL            as Base64.URL
import qualified Data.ByteString.Char8                 as BC8
import           Data.Functor                          ((<$>))
import qualified Data.HashMap.Strict                   as HMS
import           Data.Maybe                            (fromMaybe, isJust)
import           Data.Monoid                           ((<>))
import           Data.String                           (fromString)
import           Safe                                  (readMay)
import           Snap.Core                             (Snap)
import qualified Snap.Core                             as Snap
import qualified Snap.Http.Server                      as Snap
import qualified Snap.Blaze                            as Snap
import           System.FilePath                       ((</>))
import           System.IO.Error                       (isDoesNotExistError)
import           Text.Blaze.Html5                      ((!))
import qualified Text.Blaze.Html5                      as H
import qualified Text.Blaze.Html5.Attributes           as A

------------------------------------------------------------------------
-- Types
------------------------------------------------------------------------

type LockName = String

data Lock = Lock
    { lockStatus   :: LockStatus
    }
    deriving (Eq, Ord, Show, Read)

data LockStatus
    = Locked B.ByteString       -- Secret
             String             -- Locker
    | Available
    deriving (Eq, Ord, Show, Read)

lockAvailable :: Lock -> Bool
lockAvailable (Lock Available) = True
lockAvailable _                = False

------------------------------------------------------------------------
-- Utils
------------------------------------------------------------------------

returnWith :: Int -> Snap a
returnWith code = do
    Snap.modifyResponse $ Snap.setResponseCode code
    Snap.withResponse Snap.finishWith

getParam :: B.ByteString -> Snap B.ByteString
getParam paramName =
    maybe (returnWith 400) return =<< Snap.getParam paramName

readFileIfExists :: FilePath -> IO (Maybe String)
readFileIfExists fp = (Just <$> readFile fp) `catch` handleExists
  where
    handleExists e =
        if isDoesNotExistError e
        then return Nothing
        else throwIO e

makeSecret :: IO B.ByteString
makeSecret = do
    gen <- newGenIO :: IO HashDRBG
    case genBytes 3 gen of
      Left  err     -> error $ "Error generating secret: " ++ show err
      Right (bs, _) -> return $ BC8.filter (/= '=') $ Base64.URL.encode bs

------------------------------------------------------------------------
-- Write and read lock status
------------------------------------------------------------------------

readLockStatus :: FilePath -> LockName -> IO LockStatus
readLockStatus dataDir lock = do
    mbFile <- readFileIfExists (dataDir </> lock)
    case mbFile of
      Nothing   -> return Available
      Just file -> case readMay file of
        Just status -> return status
        Nothing     -> error $ "Corrupted status for lock " ++ show lock

writeLockStatus :: FilePath -> LockName -> LockStatus -> IO ()
writeLockStatus dataDir name status = do
    writeFile (dataDir </> name) $ show status

------------------------------------------------------------------------
-- Html rendering
------------------------------------------------------------------------

type RenderEnv = [(LockName, Lock, Maybe B.ByteString)]

lockLockForm :: LockName -> Lock -> H.Html
lockLockForm name lock =
    case lockStatus lock of
      Available ->
        H.form ! A.action (fromString ("/lock/" ++ name)) ! A.method "POST" $ do
          H.input ! A.type_ "text" ! A.name "user"
          H.input ! A.type_ "submit" ! A.value "Lock"
      Locked _ _ ->
        return ()

releaseLockForm :: LockName -> Lock -> Maybe B.ByteString -> H.Html
releaseLockForm name lock mbSecret =
    case lockStatus lock of
      Available  -> return ()
      Locked _ _ ->
        H.form ! A.action (fromString ("/release/" ++ name ++ query)) ! A.method "POST" $ do
            H.input ! A.type_ "submit" ! A.value text
  where
    query = case mbSecret of
      Nothing      -> "?force=1"
      Just _secret -> ""
    text = case mbSecret of
      Nothing      -> "Force release"
      Just _secret -> "Release"

renderBody :: RenderEnv -> String -> H.Html -> H.Html
renderBody env title body = do
    H.head $ do
      H.title $ H.toMarkup title
    H.body $ do
      body
      H.hr
      H.ul $ do
        forM_ env $ \(name, lock, mbSecret) ->
          H.li $ do
            H.b (fromString name)
            " - " >> case lockStatus lock of
               Available     -> "Available"
               Locked _ user -> H.toHtml $ "Locked by " ++ user
            releaseLockForm name lock mbSecret
            lockLockForm name lock

renderAlreadyLocked :: LockName -> String -> RenderEnv -> H.Html
renderAlreadyLocked name user env =
    renderBody env (name ++ " is already locked!") $ do
      H.toHtml $ name ++ " is already locked by " ++ user ++ "."

renderLockedSuccesfully :: LockName -> B.ByteString -> RenderEnv -> H.Html
renderLockedSuccesfully name secret env =
    renderBody env (name ++ " was locked successfully!") $ do
      H.toHtml $ name ++ " was locked successfully!"
      H.br
      H.toHtml $ "Your secret is " ++ show secret

renderAlreadyReleased :: LockName -> RenderEnv -> H.Html
renderAlreadyReleased name env =
    renderBody env (name <> " is available!") $ do
      H.toHtml $ "I can't release " ++ name ++ ", because it's already released."

renderReleased :: LockName -> RenderEnv -> H.Html
renderReleased name env =
    renderBody env (name ++ " has been released.") $ do
      H.toHtml $ name ++ " has now been released."

renderWrongCredentials :: RenderEnv -> H.Html
renderWrongCredentials env =
    renderBody env "Wrong credentials" "Wrong credentials"

------------------------------------------------------------------------
-- Cookie
------------------------------------------------------------------------

readSecretCookie :: LockName -> Snap (Maybe B.ByteString)
readSecretCookie name = runMaybeT $ do
    let cookieName = BC8.pack name
    cookie <- MaybeT (Snap.withResponse $ return . Snap.getResponseCookie cookieName) <|>
              MaybeT (Snap.getCookie cookieName)
    let value = Snap.cookieValue cookie
    when (B.null value) mzero
    return $ value

writeSecretCookie :: LockName -> B.ByteString -> Snap ()
writeSecretCookie name secret =
    Snap.modifyResponse $ Snap.addResponseCookie Snap.Cookie
      { Snap.cookieName     = BC8.pack name
      , Snap.cookieValue    = secret
      , Snap.cookieExpires  = Just (read "2020-01-01 00:00:00.000000 UTC")
      , Snap.cookieDomain   = Nothing
      , Snap.cookiePath     = Just "/"
      , Snap.cookieSecure   = False
      , Snap.cookieHttpOnly = False
      }

deleteSecretCookie :: LockName -> Snap ()
deleteSecretCookie name = Snap.expireCookie (BC8.pack name) Nothing

------------------------------------------------------------------------
-- Snap
------------------------------------------------------------------------

type Locks = HMS.HashMap LockName Lock
type Action a = FilePath -> MVar Locks -> a

runRender :: Locks -> (RenderEnv -> H.Html) -> Snap ()
runRender locks r = do
    env <- forM (HMS.toList locks) $ \(name, lock) -> do
      mbSecret <- readSecretCookie name
      return (name, lock, mbSecret)
    Snap.blaze $ r env

lockLock :: Action (LockName -> Snap ())
lockLock dataDir locksMV name = Snap.method Snap.POST $ do
    user <- BC8.unpack <$> getParam "user"
    join $ liftIO $ modifyMVar locksMV $ \locks ->
      case HMS.lookup name locks of
        Nothing   -> return (locks, returnWith 404)
        Just lock ->
          case lockStatus lock of
            Locked _secret user' ->
              return ( locks
                     ,  do runRender locks $ renderAlreadyLocked name user'
                           returnWith 400
                     )
            Available -> do
              secret <- makeSecret
              let status = Locked secret user
              let locks' = HMS.insert name lock{lockStatus = status} locks
              writeLockStatus dataDir name status
              return ( locks'
                     , do writeSecretCookie name secret
                          runRender locks' $ renderLockedSuccesfully name secret
                     )

releaseLock :: Action (LockName -> Snap ())
releaseLock dataDir locksMV name = Snap.method Snap.POST $ do
    force <- fromMaybe False . fmap (const True) <$> Snap.getParam "force"
    mbSecret <- readSecretCookie name
    join $ liftIO $ modifyMVar locksMV $ \locks -> do
      case HMS.lookup name locks of
        Nothing   -> return (locks, returnWith 404)
        Just lock ->
          case lockStatus lock of
            Available ->
              return ( locks
                     , do deleteSecretCookie name
                          runRender locks $ renderAlreadyReleased name
                          returnWith 400
                     )
            Locked secret _user | force || Just secret == mbSecret -> do
              writeLockStatus dataDir name Available
              let locks' = HMS.insert name lock{lockStatus = Available} locks
              return ( locks'
                     , do deleteSecretCookie name
                          runRender locks' $ renderReleased name
                     )
            Locked _secret _user ->
              return ( locks
                     , do when (isJust mbSecret) $ deleteSecretCookie name
                          runRender locks renderWrongCredentials
                          returnWith 403
                     )

listLocks :: MVar Locks -> Snap ()
listLocks locksMV = do
    locks <- liftIO $ readMVar locksMV
    runRender locks $ \env -> renderBody env "Index" $ return ()

run :: Action (Snap ())
run dataDir locksMV =
    Snap.route [ ("lock/:lock",    runAction lockLock   )
               , ("release/:lock", runAction releaseLock)
               , ("/",             listLocks locksMV    )
               ]
  where
    runAction m = m dataDir locksMV . BC8.unpack =<< getParam "lock"


main :: IO ()
main = do
    let locksFile = "locks"
    let dataDir   = "data"
    locksList <- read <$> readFile locksFile
    locks <- forM locksList $ \name -> do
      status <- readLockStatus dataDir name
      return (name, Lock status)
    locksMV <- newMVar $ HMS.fromList locks
    Snap.quickHttpServe $ run dataDir locksMV
