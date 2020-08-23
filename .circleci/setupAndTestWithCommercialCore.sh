coreInfo=`curl -s -X GET \
"https://api.supertokens.io/0/core/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $coreInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for core, X.Y version: $1, planType: COMMERCIAL gave response: $coreInfo"
    exit 1
fi
coreTag=$(echo $coreInfo | jq .tag | tr -d '"')
coreVersion=$(echo $coreInfo | jq .version | tr -d '"')

pluginInterfaceVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/core/dependency/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceVersionXY | jq .pluginInterface` == "null" ]]
then
    echo "fetching latest X.Y version for plugin-interface, given core X.Y version: $1, planType: COMMERCIAL gave response: $pluginInterfaceVersionXY"
    exit 1
fi
pluginInterfaceVersionXY=$(echo $pluginInterfaceVersionXY | jq .pluginInterface | tr -d '"')

pluginInterfaceInfo=`curl -s -X GET \
"https://api.supertokens.io/0/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$pluginInterfaceVersionXY" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for plugin-interface, X.Y version: $pluginInterfaceVersionXY, planType: COMMERCIAL gave response: $pluginInterfaceInfo"
    exit 1
fi
pluginInterfaceTag=$(echo $pluginInterfaceInfo | jq .tag | tr -d '"')
pluginInterfaceVersion=$(echo $pluginInterfaceInfo | jq .version | tr -d '"')

pluginVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/plugin-interface/dependency/plugin/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$pluginInterfaceVersionXY&pluginName=mysql" \
-H 'api-version: 0'`
if [[ `echo $pluginVersionXY | jq .plugin` == "null" ]]
then
    echo "fetching latest X.Y version for mysql given plugin-interface X.Y version: $pluginInterfaceVersionXY gave response: $pluginVersionXY"
    exit 1
fi
pluginVersionXY=$(echo $pluginVersionXY | jq .plugin | tr -d '"')
        
pluginInfo=`curl -s -X GET \
"https://api.supertokens.io/0/plugin/latest?password=$SUPERTOKENS_API_KEY&planType=COMMERCIAL&mode=DEV&version=$pluginVersionXY&name=mysql" \
-H 'api-version: 0'`
if [[ `echo $pluginInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for mysql, X.Y version: $pluginVersionXY gave response: $pluginInfo"
    exit 1
fi
pluginTag=$(echo $pluginInfo | jq .tag | tr -d '"')
pluginVersion=$(echo $pluginInfo | jq .version | tr -d '"')

echo "Testing with node driver: $2, COMMERCIAL core: $coreVersion, plugin-interface: $pluginInterfaceVersion, mysql plugin: $pluginVersion"

cd ../../
git clone git@bitbucket.org:vrai-labs/com-root.git
cd com-root
echo -e "core,$1\nplugin-interface,$pluginInterfaceVersionXY\nmysql-plugin,$pluginVersionXY" > modules.txt
./loadModules --ssh
cd com-core
git checkout $coreTag
cd ../com-plugin-interface
git checkout $pluginInterfaceTag
cd ../com-mysql-plugin
git checkout $pluginTag
cd ../
echo $SUPERTOKENS_API_KEY > apiPassword
./utils/setupTestEnvLocal
cd ../project/test/server/
npm i -d
npm i git+https://github.com:supertokens/supertokens-node.git#$2
cd ../../
INSTALL_PATH=../com-root npm run test
if [[ $? -ne 0 ]]
then
    echo "test failed... exiting!"
    exit 1
fi
kill -15 $pid