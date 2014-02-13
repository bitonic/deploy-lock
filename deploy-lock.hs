{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
import           Prelude                               hiding (catch)

import           Control.Applicative                   ((<|>))
import           Control.Concurrent.MVar               (MVar, newMVar, modifyMVar, withMVar, readMVar)
import           Control.Exception                     (throwIO, catch)
import           Control.Monad                         (forM, mzero, when, forM_, join, void)
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

data RenderEnv = RenderEnv
    { reLockName :: LockName
    , reLock     :: Lock
    , reSecret   :: Maybe B.ByteString
    }

displayLockLink' :: LockName -> H.Html
displayLockLink' name =
    H.a ! A.href (fromString ("/status/" ++ name)) $ "Status"

displayLockLink :: RenderEnv -> H.Html
displayLockLink = displayLockLink' . reLockName

lockLockForm :: RenderEnv -> H.Html
lockLockForm env =
    H.form ! A.action (fromString ("/lock/" ++ reLockName env)) ! A.method "GET" $ do
      H.input ! A.type_ "text" ! A.name "user"
      H.input ! A.type_ "submit" ! A.value "Lock"

releaseLockLink :: RenderEnv -> H.Html
releaseLockLink env =
    case lockStatus (reLock env) of
      Available  -> return ()
      Locked _ _ ->
        H.a ! A.href (fromString ("/release/" ++ reLockName env ++ query))
            $ H.toHtml text
  where
    query = case reSecret env of
      Nothing      -> "?force=1"
      Just _secret -> ""
    text :: String = case reSecret env of
      Nothing      -> "Force release"
      Just _secret -> "Release"

renderBody :: String -> H.Html -> H.Html
renderBody title body = H.html $ do
     H.head $ do
         H.title $ H.toMarkup title
         -- link ! rel "stylesheet" ! type_ "text/css" ! href "screen.css"
     H.body $ body

renderLockBody :: RenderEnv -> String -> H.Html -> H.Html
renderLockBody env title body = renderBody title $ do
    H.b $ H.toHtml $ reLockName env
    void $ " - "
    displayLockLink env
    void $ if lockAvailable (reLock env) then "" else " - "
    releaseLockLink env
    lockLockForm env
    H.hr
    body

renderDisplayLock :: RenderEnv -> H.Html
renderDisplayLock env =
    renderLockBody env ("Lock " ++ reLockName env) $ do
      H.h1 $ H.toHtml $ reLockName env ++ " status"
      H.h2 $ H.toHtml $ case lockStatus (reLock env) of
        Available           -> "Available"
        Locked _secret user -> "Taken by " ++ user

renderAlreadyLocked :: String -> RenderEnv -> H.Html
renderAlreadyLocked user env =
    renderLockBody env (reLockName env ++ " is already locked!") $ do
      H.toHtml $ reLockName env ++ " is already locked by " ++ user ++ "."

renderLockedSuccesfully :: B.ByteString -> RenderEnv -> H.Html
renderLockedSuccesfully secret env =
    renderLockBody env (reLockName env ++ " was locked successfully!") $ do
      H.toHtml $ reLockName env ++ " was locked successfully!"
      H.br
      H.toHtml $ "Your secret is " ++ show secret

renderAlreadyReleased :: RenderEnv -> H.Html
renderAlreadyReleased env =
    renderLockBody env (reLockName env <> " is available!") $ do
      H.toHtml $ "I can't release " ++ reLockName env ++
                 ", because it's already released."

renderReleased :: RenderEnv -> H.Html
renderReleased env =
    renderLockBody env (reLockName env ++ " has been released.") $ do
      H.toHtml $ reLockName env ++ " has now been released."

renderWrongCredentials :: RenderEnv -> H.Html
renderWrongCredentials env =
    renderLockBody env "Wrong credentials" "Wrong credentials"

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

runRender :: LockName -> Lock -> (RenderEnv -> H.Html) -> Snap ()
runRender name lock r = do
    mbSecret <- readSecretCookie name
    Snap.blaze $ r $ RenderEnv name lock mbSecret

displayLock :: Action (LockName -> Snap ())
displayLock _dataDir locksMV name = do
    locks <- liftIO $ readMVar locksMV
    case HMS.lookup name locks of
      Nothing   -> returnWith 404
      Just lock -> runRender name lock renderDisplayLock

lockLock :: Action (LockName -> Snap ())
lockLock dataDir locksMV name = do
    user <- BC8.unpack <$> getParam "user"
    join $ liftIO $ modifyMVar locksMV $ \locks ->
      case HMS.lookup name locks of
        Nothing   -> return (locks, returnWith 404)
        Just lock ->
          case lockStatus lock of
            Locked _secret user' ->
              return ( locks
                     ,  do runRender name lock $ renderAlreadyLocked user'
                           returnWith 400
                     )
            Available -> do
              secret <- makeSecret
              let status = Locked secret user
              let lock'  = lock{lockStatus = status}
              writeLockStatus dataDir name status
              return ( HMS.insert name lock' locks
                     , do writeSecretCookie name secret
                          runRender name lock' $ renderLockedSuccesfully secret
                     )

releaseLock :: Action (LockName -> Snap ())
releaseLock dataDir locksMV name = do
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
                          runRender name lock renderAlreadyReleased
                          returnWith 400
                     )
            Locked secret _user | force || Just secret == mbSecret -> do
              writeLockStatus dataDir name Available
              let lock' = lock{lockStatus = Available}
              return ( HMS.insert name lock' locks
                     , do deleteSecretCookie name
                          runRender name lock' renderReleased
                     )
            Locked _secret _user ->
              return ( locks
                     , do when (isJust mbSecret) $ deleteSecretCookie name
                          runRender name lock renderWrongCredentials
                          returnWith 403
                     )

listLocks :: MVar Locks -> Snap ()
listLocks locksMV = do
    locks <- liftIO $ withMVar locksMV $ return . HMS.keys
    Snap.blaze $ renderBody "Locks" $ H.ul $ forM_ locks $ \name -> H.li $ do
      H.b (fromString name)
      " " >> displayLockLink' name

run :: Action (Snap ())
run dataDir locksMV =
    Snap.route [ ("status/:lock",  runAction displayLock)
               , ("lock/:lock",    runAction lockLock   )
               , ("release/:lock", runAction releaseLock)
               , ("/",             listLocks locksMV)
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
