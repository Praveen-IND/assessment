from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, NoteSerializer
from .models import User, Note
from django.contrib.auth.hashers import make_password,check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication  
from rest_framework.exceptions import AuthenticationFailed
from jwt import InvalidTokenError
from rest_framework_simplejwt.backends import TokenBackend

from django.conf import settings
import jwt
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView

class custom_jwt_authentication(JWTAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header or not auth_header.startswith('Bearer '):
            raise AuthenticationFailed({'error': 'Authorization header missing or malformed'})

        raw_token = auth_header.split(' ')[1]

        try:
            decoded_data = TokenBackend(
                algorithm=settings.SIMPLE_JWT.get('ALGORITHM', 'HS256'),
                signing_key=settings.SIMPLE_JWT.get('SIGNING_KEY', settings.SECRET_KEY)
            ).decode(raw_token, verify=True)

            user_id = decoded_data.get('user_id') 
            try:
                user = User.objects.get(user_id=user_id)
            except User.DoesNotExist:
                raise AuthenticationFailed({'error': 'User not found'})

            return (user, raw_token) 

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed({'error': 'Token has expired'})
        except jwt.InvalidTokenError:
            raise AuthenticationFailed({'error': 'Invalid token'})
        except Exception as e:
            raise AuthenticationFailed({'error': f'Token error: {str(e)}'})
        

class UserRegister(APIView):
    def post(self, request):
        request.data['password'] = make_password(request.data['password'])
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)



class UserLogin(APIView):
    def post(self, request):
        user_name = request.data.get('user_name')
        password = request.data.get('password')

        if not user_name or not password:
            return Response({'error': 'Username and password are required'}, status=400)

        try:
            user = User.objects.get(user_name=user_name)
        except User.DoesNotExist:
            return Response({'error': 'Invalid username or password'}, status=401)

        if check_password(password, user.password):
            refresh = RefreshToken.for_user(user)

            refresh['user_id'] = str(user.user_id)
            refresh['user_name'] = user.user_name

            return Response({
                'message': 'Login successful',
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user_id': str(user.user_id),
                'user_name': user.user_name,
            }, status=200)
        else:
            return Response({'error': 'Invalid username or password'}, status=401)

class get_put_delete(APIView):
    authentication_classes = [custom_jwt_authentication]
    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    def put(self, request):
        try:
            user = User.objects.get(user_id=request.data['user_id'])
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=200)
            return Response(serializer.errors, status=400)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
    def delete(self, request):
        try:
            user = User.objects.get(user_id=request.data['user_id'])
            user.delete()
            return Response({"message": "User deleted successfully"}, status=204)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)







class NoteListCreateView(ListCreateAPIView):
    authentication_classes = [custom_jwt_authentication]
    queryset = Note.objects.all()
    serializer_class = NoteSerializer


class NoteDetailView(RetrieveUpdateDestroyAPIView):
    authentication_classes = [custom_jwt_authentication]
    queryset = Note.objects.all()
    serializer_class = NoteSerializer
    lookup_field = 'note_id' 

