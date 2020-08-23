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
  accessTokenValidity = 1,
  enableAntiCsrf = true
) {
  let instance = axios.create();
  let response = await instance.post(module.exports.BASE_URL + '/startST', {
    accessTokenValidity,
    enableAntiCsrf
  });
  return response.data;
};
