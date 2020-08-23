let axios = require('axios');

export const BASE_URL = 'http://localhost:8080';
export const delay = function (sec) {
  return new Promise(res => setTimeout(res, sec * 1000));
};

export const expectToHaveBeenCalledWithAuth0ClientParam = (mock, expected) => {
  const [[url]] = (<jest.Mock>mock).mock.calls;
  const param = new URL(url).searchParams.get('auth0Client');
  const decodedParam = decodeURIComponent(atob(param));
  const actual = JSON.parse(decodedParam);
  expect(actual).toStrictEqual(expected);
};

export const startST = async function (
  accessTokenValidity = 3600,
  enableAntiCsrf = true
) {
  jest.setTimeout(30000);
  let instance = axios.create();
  let response = await instance.post(
    module.exports.BASE_URL + '/startST',
    {
      accessTokenValidity,
      enableAntiCsrf
    },
    {
      timeout: 60 * 4 * 1000
    }
  );
  return response.data;
};
